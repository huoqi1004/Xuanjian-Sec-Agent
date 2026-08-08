const path = require('path');
const fs = require('fs');
const logger = require('../utils/logger');

const DB_DIR = path.resolve(__dirname, '../../data');
const DB_PATH = path.resolve(process.env.DB_PATH || path.join(DB_DIR, 'security.db.json'));

if (!fs.existsSync(DB_DIR)) {
  fs.mkdirSync(DB_DIR, { recursive: true });
}
// 确保 DB_PATH 的父目录存在（env DB_PATH 可能指向任意相对/绝对路径）
const DB_PATH_DIR = path.dirname(DB_PATH);
if (!fs.existsSync(DB_PATH_DIR)) {
  fs.mkdirSync(DB_PATH_DIR, { recursive: true });
}

let db;
let tables = {};

// 持久化开关：测试环境(NODE_ENV=test)或显式 PERSIST_DB=0 时禁用
const persistEnabled = process.env.NODE_ENV !== 'test' && process.env.PERSIST_DB !== '0';
let persistTimer = null;

const uniqueConstraints = {
  users: ['username'],
  roles: ['name'],
  virus_hashes: ['hash_value'],
  sys_config: ['key'],
  edge_devices: ['device_id'],
  djpp_tasks: ['id'],
  djpp_results: ['task_id', 'check_id'],
  reports: ['id']
};

const defaultValues = {
  users: {
    department: '',
    org_id: 1,
    status: 1,
    created_at: () => new Date().toISOString(),
    updated_at: () => new Date().toISOString()
  },
  roles: {
    description: '',
    permissions: '[]'
  },
  scan_tasks: {
    scan_mode: 'tcp_connect',
    port_range: '1-1024',
    status: 'pending',
    progress: 0,
    created_at: () => new Date().toISOString()
  },
  scan_results: {
    service: '',
    version: '',
    banner: '',
    state: 'open',
    created_at: () => new Date().toISOString()
  },
  virus_scan_records: {
    detection_result: 'clean',
    created_at: () => new Date().toISOString()
  },
  threat_intel: {
    confidence: 0.5,
    updated_at: () => new Date().toISOString()
  },
  alert_records: {
    severity: 'medium',
    status: 'new',
    created_at: () => new Date().toISOString()
  },
  auto_policies: {
    cooldown: 300,
    unattended: false,
    enabled: true,
    approval_status: 'approved',
    created_at: () => new Date().toISOString()
  },
  action_logs: {
    result: 'success',
    executed_at: () => new Date().toISOString()
  },
  policy_approvals: {
    status: 'pending',
    created_at: () => new Date().toISOString()
  },
  edge_devices: {
    device_type: 'gateway',
    online_status: 0,
    metrics: '{}',
    agent_version: '',
    registered_at: () => new Date().toISOString()
  },
  device_commands: {
    params: '{}',
    status: 'pending',
    created_at: () => new Date().toISOString()
  },
  audit_logs: {
    result: 'success',
    created_at: () => new Date().toISOString()
  },
  sys_config: {
    version: 1,
    updated_at: () => new Date().toISOString()
  },
  baseline_results: {
    status: 'fail',
    severity: 'medium',
    created_at: () => new Date().toISOString()
  }
};

function initTables() {
  tables = {
    users: [],
    roles: [],
    role_permissions: [],
    scan_tasks: [],
    scan_results: [],
    baseline_policies: [],
    baseline_results: [],
    virus_scan_records: [],
    virus_hashes: [],
    threat_intel: [],
    alert_records: [],
    auto_policies: [],
    action_logs: [],
    policy_approvals: [],
    edge_devices: [],
    device_commands: [],
    audit_logs: [],
    sys_config: [],
    reports: [],
    djpp_levels: [],
    djpp_categories: [],
    djpp_checks: [],
    djpp_tasks: [],
    djpp_results: []
  };
}

/* ---------------- 持久化（JSON 落盘） ---------------- */

/**
 * 解析 VALUES 子句中的字面量（无占位符参数的 INSERT 使用，如 INSERT ... VALUES ('a', 1)）
 */
function parseValuesArray(sql) {
  const valuesMatch = sql.match(/VALUES\s*\((.+)\)/i);
  if (!valuesMatch) return [];
  const rawValues = valuesMatch[1];
  const valueParts = [];
  let current = '';
  let inQuotes = false;
  let quoteChar = '';
  for (let i = 0; i < rawValues.length; i++) {
    const ch = rawValues[i];
    if ((ch === "'" || ch === '"') && (i === 0 || rawValues[i - 1] !== '\\')) {
      if (!inQuotes) {
        inQuotes = true;
        quoteChar = ch;
      } else if (ch === quoteChar) {
        inQuotes = false;
      }
      current += ch;
    } else if (ch === ',' && !inQuotes) {
      valueParts.push(current.trim());
      current = '';
    } else {
      current += ch;
    }
  }
  if (current.trim()) valueParts.push(current.trim());

  return valueParts.map((val) => {
    if (val === 'NULL') return null;
    if (val === 'true' || val === 'TRUE') return 1;
    if (val === 'false' || val === 'FALSE') return 0;
    if (/^-?\d+(\.\d+)?$/.test(val)) return Number(val);
    if ((val.startsWith("'") && val.endsWith("'")) || (val.startsWith('"') && val.endsWith('"'))) return val.slice(1, -1);
    return val;
  });
}

/**
 * 启动时加载持久化数据（若文件存在）
 */
function loadPersisted() {
  if (!persistEnabled) return false;
  try {
    if (fs.existsSync(DB_PATH)) {
      const raw = fs.readFileSync(DB_PATH, 'utf8');
      const data = JSON.parse(raw);
      if (data && typeof data === 'object' && data.tables) {
        // 兼容 { tables: {...} } 与旧版 { tables: [...] } 两种形态
        const restored = Array.isArray(data.tables) ? {} : data.tables;
        if (Array.isArray(data.tables)) {
          Object.keys(tables).forEach((name, idx) => {
            restored[name] = data.tables[idx] || [];
          });
        }
        // 仅恢复已知表，未知表忽略
        Object.keys(tables).forEach((name) => {
          if (Array.isArray(restored[name])) tables[name] = restored[name];
        });
        logger.info(`数据库已从 ${DB_PATH} 恢复 ${Object.keys(restored).length} 张表`);
        return true;
      }
    }
  } catch (err) {
    logger.warn(`数据库持久化加载失败（忽略并重建）: ${err.message}`);
  }
  return false;
}

/**
 * 将全部表数据落盘到 JSON 文件
 */
function persist() {
  if (!persistEnabled) return;
  try {
    fs.mkdirSync(DB_PATH_DIR, { recursive: true });
    const tmpPath = `${DB_PATH}.tmp`;
    fs.writeFileSync(tmpPath, JSON.stringify({ tables, savedAt: new Date().toISOString() }), 'utf8');
    fs.renameSync(tmpPath, DB_PATH);
  } catch (err) {
    logger.warn(`数据库持久化写入失败: ${err.message}`);
  }
}

/**
 * 写操作后防抖落盘（聚合高频写入，避免频繁 IO）
 */
function schedulePersist() {
  if (!persistEnabled) return;
  if (persistTimer) clearTimeout(persistTimer);
  persistTimer = setTimeout(() => {
    persistTimer = null;
    persist();
  }, 800);
}

/**
 * 测试/调试用：重置全部内存表并清空持久化文件
 */
function resetForTest() {
  initTables();
  if (persistTimer) clearTimeout(persistTimer);
  if (persistEnabled && fs.existsSync(DB_PATH)) {
    try { fs.unlinkSync(DB_PATH); } catch (e) {}
  }
  logger.info('测试数据库已重置');
}

function parseJoinQuery(sql) {
  const normalizedSql = sql.replace(/\s+/g, ' ').trim();
  const joinMatch = normalizedSql.match(/SELECT\s+([\s\S]+?)\s+FROM\s+(\w+)\s+(\w+)\s+(?:LEFT\s+)?JOIN\s+(\w+)\s+(\w+)\s+ON\s+([\s\S]+)/i);
  if (!joinMatch) return null;
  
  const [, rawSelectPart, table1, alias1, table2, alias2, remainingClause] = joinMatch;
  const isLeftJoin = /LEFT\s+JOIN/i.test(normalizedSql);
  
  const selectPart = rawSelectPart.trim();
  
  const onMatch = remainingClause.match(/(\w+)\.(\w+)\s*=\s*(\w+)\.(\w+)/);
  if (!onMatch) return null;
  
  const [, leftAlias, leftCol, rightAlias, rightCol] = onMatch;
  
  const selectFields = [];
  const fieldParts = selectPart.split(',').map(f => f.trim());
  
  fieldParts.forEach(field => {
    const wildcardMatch = field.match(/(\w+)\.\*/);
    if (wildcardMatch) {
      selectFields.push({ table: wildcardMatch[1], wildcard: true });
    } else {
      const fieldMatch = field.match(/(\w+)\.(\w+)(?:\s+as\s+(\w+))?/i);
      if (fieldMatch) {
        selectFields.push({ 
          table: fieldMatch[1], 
          column: fieldMatch[2], 
          alias: fieldMatch[3] || fieldMatch[2] 
        });
      }
    }
  });
  
  let whereCondition = null;
  let orderClause = null;
  let limitClause = null;
  let offsetClause = null;
  
  const whereMatch = remainingClause.match(/WHERE\s+([\s\S]+?)(?:ORDER\s+BY|$)/i);
  if (whereMatch) {
    const whereStr = whereMatch[1].trim();
    const paramMatch = whereStr.match(/(\w+)\.(\w+)\s*=\s*\?/);
    if (paramMatch) {
      whereCondition = { table: paramMatch[1], column: paramMatch[2], isParam: true };
    } else {
      const literalMatch = whereStr.match(/(\w+)\.(\w+)\s*=\s*['"]?([^'"\s]+)['"]?/);
      if (literalMatch) {
        whereCondition = { table: literalMatch[1], column: literalMatch[2], value: literalMatch[3] };
      }
    }
  }
  
  const orderMatch = remainingClause.match(/ORDER\s+BY\s+([\s\S]+?)(?:LIMIT|OFFSET|$)/i);
  if (orderMatch) {
    const orderStr = orderMatch[1].trim();
    const fieldMatch = orderStr.match(/(\w+)\.(\w+)\s+(ASC|DESC)/i);
    if (fieldMatch) {
      orderClause = { table: fieldMatch[1], column: fieldMatch[2], direction: fieldMatch[3].toUpperCase() };
    } else {
      const simpleMatch = orderStr.match(/(\w+)\s+(ASC|DESC)/i);
      if (simpleMatch) {
        orderClause = { column: simpleMatch[1], direction: simpleMatch[2].toUpperCase() };
      }
    }
  }
  
  const limitMatch = remainingClause.match(/LIMIT\s+(\?|\d+)/i);
  if (limitMatch) {
    limitClause = limitMatch[1] === '?' ? null : parseInt(limitMatch[1]);
  }
  
  const offsetMatch = remainingClause.match(/OFFSET\s+(\?|\d+)/i);
  if (offsetMatch) {
    offsetClause = offsetMatch[1] === '?' ? null : parseInt(offsetMatch[1]);
  }
  
  return {
    selectFields,
    table1,
    alias1,
    table2,
    alias2,
    joinOn: { leftAlias, leftCol, rightAlias, rightCol },
    where: whereCondition,
    isLeftJoin,
    order: orderClause,
    limit: limitClause,
    offset: offsetClause
  };
}

function executeJoinQuery(query, params) {
  const { selectFields, table1, alias1, table2, alias2, joinOn, where, isLeftJoin, order, limit, offset } = query;
  
  const table1Data = tables[table1] || [];
  const table2Data = tables[table2] || [];
  
  let filteredTable1 = table1Data;
  if (where) {
    let filterValue;
    if (where.isParam) {
      const flatParams = params.flat();
      filterValue = flatParams[0];
    } else {
      filterValue = where.value;
    }
    const filterCol = where.column;
    filteredTable1 = table1Data.filter(row => {
      const rowVal = row[filterCol];
      if (typeof rowVal === 'number') {
        return rowVal === Number(filterValue);
      }
      return rowVal == filterValue;
    });
  }
  
  const results = [];
  
  filteredTable1.forEach(row1 => {
    const joinValue = row1[joinOn.leftCol];
    const matchingRow2 = table2Data.find(row2 => {
      const row2Val = row2[joinOn.rightCol];
      if (typeof row2Val === 'number' && typeof joinValue === 'number') {
        return row2Val === joinValue;
      }
      return row2[joinOn.rightCol] == joinValue;
    });
    
    if (matchingRow2 || isLeftJoin) {
      const result = {};
      selectFields.forEach(field => {
        if (field.wildcard) {
          const sourceRow = field.table === alias1 ? row1 : (matchingRow2 || {});
          Object.keys(sourceRow).forEach(key => {
            result[key] = sourceRow[key];
          });
        } else {
          const sourceRow = field.table === alias1 ? row1 : (matchingRow2 || {});
          result[field.alias || field.column] = sourceRow[field.column];
        }
      });
      results.push(result);
    }
  });
  
  if (order) {
    const orderCol = order.column;
    const orderDir = order.direction === 'DESC' ? -1 : 1;
    results.sort((a, b) => {
      const valA = a[orderCol] || '';
      const valB = b[orderCol] || '';
      if (valA < valB) return -1 * orderDir;
      if (valA > valB) return 1 * orderDir;
      return 0;
    });
  }
  
  const flatParams = params.flat();
  let actualLimit = limit;
  let actualOffset = offset || 0;
  
  if (actualLimit === null) {
    const limitIdx = flatParams.length - (actualOffset === null ? 1 : 2);
    if (limitIdx >= 0) {
      actualLimit = parseInt(flatParams[limitIdx]) || 100;
    } else {
      actualLimit = 100;
    }
  }
  if (actualOffset === null) {
    const offsetIdx = flatParams.length - 1;
    if (offsetIdx >= 0) {
      actualOffset = parseInt(flatParams[offsetIdx]) || 0;
    } else {
      actualOffset = 0;
    }
  }
  
  if (actualLimit !== null && actualLimit !== undefined) {
    return results.slice(actualOffset, actualOffset + actualLimit);
  }
  
  return results;
}

function getDb() {
  if (!db) {
    initTables();
    loadPersisted();
    db = {
      exec: function(sql) {
        if (sql.startsWith('CREATE TABLE')) {
          const tableNameMatch = sql.match(/CREATE TABLE IF NOT EXISTS (\w+)/);
          if (tableNameMatch && !tables[tableNameMatch[1]]) {
            tables[tableNameMatch[1]] = [];
          }
        } else if (sql.startsWith('CREATE INDEX')) {
        } else if (sql.trim().toUpperCase().startsWith('INSERT')) {
          const isIgnore = sql.toUpperCase().includes('INSERT OR IGNORE');
          const tableNameMatch = sql.match(/INSERT(?:\s+OR\s+IGNORE)?\s+INTO\s+(\w+)/i);
          if (tableNameMatch) {
            const tableName = tableNameMatch[1];
            const columnsMatch = sql.match(/\(([^)]+)\)/);
            if (columnsMatch) {
              const columns = columnsMatch[1].split(',').map(c => c.trim());
              const valuesMatch = sql.match(/VALUES\s*\((.+)\)/i);
              if (valuesMatch) {
                const rawValues = valuesMatch[1];
                const row = {};
                const valueParts = [];
                let current = '';
                let inQuotes = false;
                let quoteChar = '';
                for (let i = 0; i < rawValues.length; i++) {
                  const ch = rawValues[i];
                  if ((ch === "'" || ch === '"') && (i === 0 || rawValues[i-1] !== '\\')) {
                    if (!inQuotes) {
                      inQuotes = true;
                      quoteChar = ch;
                    } else if (ch === quoteChar) {
                      inQuotes = false;
                    }
                    current += ch;
                  } else if (ch === ',' && !inQuotes) {
                    valueParts.push(current.trim());
                    current = '';
                  } else {
                    current += ch;
                  }
                }
                if (current.trim()) valueParts.push(current.trim());
                
                columns.forEach((col, idx) => {
                  let val = valueParts[idx];
                  if (val === undefined || val === 'undefined') {
                    val = null;
                  } else if (val === 'NULL') {
                    val = null;
                  } else if (val === 'true' || val === 'TRUE') {
                    val = 1;
                  } else if (val === 'false' || val === 'FALSE') {
                    val = 0;
                  } else if (/^-?\d+(\.\d+)?$/.test(val)) {
                    val = Number(val);
                  } else if ((val.startsWith("'") && val.endsWith("'")) || (val.startsWith('"') && val.endsWith('"'))) {
                    val = val.slice(1, -1);
                  }
                  row[col] = val;
                });
                
                if (!tables[tableName]) tables[tableName] = [];
                tables[tableName].push(row);
              }
            }
          }
        }
      },
      
      prepare: function(sql) {
        return {
          run: function(...params) {
            const s = sql.trim();
            if (s.toUpperCase().startsWith('INSERT')) {
              const isIgnore = s.toUpperCase().includes('INSERT OR IGNORE');
              const tableNameMatch = s.match(/INSERT(?:\s+OR\s+IGNORE)?\s+INTO\s+(\w+)/i);
              if (!tableNameMatch) return { lastInsertRowid: 0, changes: 0 };
              const tableName = tableNameMatch[1];
              
              const columnsMatch = s.match(/\(([^)]+)\)/);
              if (!columnsMatch) return { lastInsertRowid: 0, changes: 0 };
              const columns = columnsMatch[1].split(',').map(c => c.trim());

              const row = {};
              const flatParams = params.flat();
              if (flatParams.length === 0) {
                // 无占位符参数时解析 VALUES 字面量（INSERT ... VALUES ('a', 1)）
                const literalValues = parseValuesArray(s);
                columns.forEach((col, idx) => {
                  row[col] = literalValues[idx] !== undefined ? literalValues[idx] : null;
                });
              } else {
                columns.forEach((col, idx) => {
                  row[col] = flatParams[idx] !== undefined ? flatParams[idx] : null;
                });
              }
              
              const defaults = defaultValues[tableName] || {};
              Object.keys(defaults).forEach(key => {
                if (row[key] === undefined || row[key] === null) {
                  row[key] = typeof defaults[key] === 'function' ? defaults[key]() : defaults[key];
                }
              });
              
              if (!tables[tableName]) tables[tableName] = [];
              
              const constraints = uniqueConstraints[tableName] || [];
              let shouldInsert = true;
              
              if (constraints.length > 0) {
                const exists = tables[tableName].some(r => {
                  return constraints.every(constraint => 
                    row[constraint] !== undefined && row[constraint] !== null && r[constraint] === row[constraint]
                  );
                });
                
                if (exists) {
                  if (isIgnore) {
                    return { lastInsertRowid: 0, changes: 0 };
                  }
                  shouldInsert = false;
                }
              }
              
              if (!shouldInsert && !isIgnore) {
                return { lastInsertRowid: 0, changes: 0 };
              }
              
              if (!row.id) row.id = (tables[tableName]?.length || 0) + 1;
              tables[tableName].push(row);
              schedulePersist();
              return { lastInsertRowid: row.id, changes: 1 };
            } else if (s.startsWith('UPDATE')) {
              const tableNameMatch = s.match(/UPDATE\s+(\w+)/i);
              if (!tableNameMatch) return { changes: 0 };
              const tableName = tableNameMatch[1];

              if (!tables[tableName]) return { changes: 0 };

              // 分离 SET 与 WHERE 子句
              const setWhereMatch = s.match(/SET\s+(.+?)\s+WHERE\s+(.+)$/i);
              if (!setWhereMatch) return { changes: 0 };
              const setClause = setWhereMatch[1];
              const whereClause = setWhereMatch[2];

              // 参数顺序按 SQL 中 ? 的出现顺序：SET 子句在前，WHERE 子句在后
              const setCols = [...setClause.matchAll(/(\w+)\s*=\s*\?/g)].map(m => m[1]);
              const whereCols = [...whereClause.matchAll(/(\w+)\s*=\s*\?/g)].map(m => m[1]);
              const flatParams = params.flat();
              if (setCols.length + whereCols.length > flatParams.length) return { changes: 0 };
              const setVals = flatParams.slice(0, setCols.length);
              const whereVals = flatParams.slice(setCols.length, setCols.length + whereCols.length);

              // 构建 SET 项: col = ?（顺序取值）或 col = 字面量
              const setItems = [];
              let setIdx = 0;
              for (const part of setClause.split(',').map(x => x.trim())) {
                const paramMatch = part.match(/^(\w+)\s*=\s*\?$/i);
                if (paramMatch) {
                  setItems.push({ col: paramMatch[1], value: setVals[setIdx++] });
                  continue;
                }
                const literalMatch = part.match(/^(\w+)\s*=\s*(.+)$/i);
                if (literalMatch) {
                  let v = literalMatch[2].trim();
                  if (v === "datetime('now')") v = new Date().toISOString();
                  else v = v.replace(/^['"]|['"]$/g, '');
                  setItems.push({ col: literalMatch[1], value: v });
                }
              }

              let changes = 0;
              tables[tableName].forEach(row => {
                const matched = whereCols.every((col, i) => row[col] == whereVals[i]);
                if (matched) {
                  setItems.forEach(({ col, value }) => { row[col] = value; });
                  changes++;
                }
              });

              if (changes > 0) schedulePersist();
              return { changes };
            } else if (s.toUpperCase().startsWith('DELETE')) {
              // DELETE 支持（WHERE 等值条件，参数或字面量）
              const tableNameMatch = s.match(/DELETE\s+FROM\s+(\w+)/i);
              if (!tableNameMatch) return { changes: 0 };
              const tableName = tableNameMatch[1];
              if (!tables[tableName]) return { changes: 0 };

              const whereMatch = s.match(/WHERE\s+([\s\S]+)$/i);
              if (!whereMatch) {
                // 无条件删除（慎用）
                const n = tables[tableName].length;
                tables[tableName] = [];
                if (n > 0) schedulePersist();
                return { changes: n };
              }
              const whereClause = whereMatch[1].trim();
              const flatParams = params.flat();

              // 形如 col = ? 的条件
              const paramConditions = [...whereClause.matchAll(/(\w+)\s*=\s*\?/g)].map((m) => m[1]);
              if (paramConditions.length > 0 && paramConditions.length <= flatParams.length) {
                const before = tables[tableName].length;
                tables[tableName] = tables[tableName].filter((row) =>
                  !paramConditions.every((col, i) => row[col] == flatParams[i])
                );
                const changes = before - tables[tableName].length;
                if (changes > 0) schedulePersist();
                return { changes };
              }

              // 形如 col = 字面量 的条件（如 WHERE id = 5）
              const literalConditions = [...whereClause.matchAll(/(\w+)\s*=\s*['"]?([^'"\s]+)['"]?/g)];
              if (literalConditions.length > 0) {
                const before = tables[tableName].length;
                tables[tableName] = tables[tableName].filter((row) =>
                  !literalConditions.every(([, col, val]) => String(row[col]) === String(val))
                );
                const changes = before - tables[tableName].length;
                if (changes > 0) schedulePersist();
                return { changes };
              }

              return { changes: 0 };
            }
            return { lastInsertRowid: 0, changes: 0 };
          },
          
          get: function(...params) {
            const joinQuery = parseJoinQuery(sql);
            if (joinQuery) {
              const results = executeJoinQuery(joinQuery, params);
              return results.length > 0 ? results[0] : undefined;
            }
            
            if (sql.toUpperCase().includes('COUNT(*)')) {
              const tableNameMatch = sql.match(/FROM\s+(\w+)/i);
              if (!tableNameMatch) return { count: 0 };
              const tableName = tableNameMatch[1];
              
              const whereMatch = sql.match(/WHERE\s+([\s\S]+?)(?:ORDER|$)/i);
              if (whereMatch) {
                const whereStr = whereMatch[1].trim();
                // 字面量恒等式（如 1=1）视为无条件条件，跳过过滤
                if (/^[\d\s]+\s*=\s*[\d\s]+$/.test(whereStr)) {
                  return { count: tables[tableName]?.length || 0 };
                }
                const paramMatch = whereStr.match(/(\w+)\s*=\s*\?/);
                if (paramMatch) {
                  const col = paramMatch[1];
                  const flatParams = params.flat();
                  const val = flatParams[0];
                  const count = tables[tableName]?.filter(row => {
                    const rowVal = row[col];
                    if (typeof rowVal === 'number') {
                      return rowVal === Number(val);
                    }
                    return String(rowVal) === String(val);
                  }).length || 0;
                  return { count };
                } else {
                  const literalMatch = whereStr.match(/(\w+)\s*=\s*['"]?([^'"\s]+)['"]?/);
                  if (literalMatch) {
                    const col = literalMatch[1];
                    const val = literalMatch[2];
                    const count = tables[tableName]?.filter(row => String(row[col]) === String(val)).length || 0;
                    return { count };
                  }
                }
              }
              
              return { count: tables[tableName]?.length || 0 };
            }
            
            if (sql.includes('SELECT * FROM')) {
              const tableNameMatch = sql.match(/FROM (\w+)/);
              if (!tableNameMatch) return {};
              const tableName = tableNameMatch[1];
              
              const whereMatch = sql.match(/WHERE\s+(\w+)\s*=\s*['"]?([^'"\s]+)['"]?/i);
              if (whereMatch) {
                const [, col, val] = whereMatch;
                const paramVal = params[0] !== undefined ? params[0] : val;
                return tables[tableName]?.find(row => row[col] == paramVal) || undefined;
              }
              
              return tables[tableName]?.[0] || undefined;
            }
            if (sql.includes('SELECT key, value')) {
              return tables.sys_config?.[0] || undefined;
            }
            
            const simpleSelect = sql.match(/SELECT\s+(\w+)\s+FROM\s+(\w+)/i);
            if (simpleSelect) {
              const [, col, table] = simpleSelect;
              const whereMatch = sql.match(/WHERE\s+(\w+)\s*=\s*['"]?([^'"\s]+)['"]?/i);
              if (whereMatch) {
                const [, whereCol, whereVal] = whereMatch;
                const paramVal = params[0] !== undefined ? params[0] : whereVal;
                const row = tables[table]?.find(r => r[whereCol] == paramVal);
                return row ? { [col]: row[col] } : undefined;
              }
              const firstRow = tables[table]?.[0];
              return firstRow ? { [col]: firstRow[col] } : undefined;
            }
            
            return undefined;
          },
          
          all: function(...params) {
            const joinQuery = parseJoinQuery(sql);
            if (joinQuery) {
              return executeJoinQuery(joinQuery, params);
            }
            
            if (sql.includes('SELECT * FROM') || sql.includes('SELECT')) {
              const tableNameMatch = sql.match(/FROM\s+(\w+)/i);
              if (!tableNameMatch) return [];
              const tableName = tableNameMatch[1];
              
              const paramWhereMatch = sql.match(/WHERE\s+(\w+)\s*=\s*\?/i);
              if (paramWhereMatch) {
                const [, col] = paramWhereMatch;
                const flatParams = params.flat();
                const val = flatParams[0];
                let results = tables[tableName]?.filter(row => {
                  const rowVal = row[col];
                  if (typeof rowVal === 'number') {
                    return rowVal === Number(val);
                  }
                  return String(rowVal) === String(val);
                }) || [];
                
                const orderMatch = sql.match(/ORDER\s+BY\s+(\w+)\s*(ASC|DESC)?/i);
                if (orderMatch) {
                  const orderCol = orderMatch[1];
                  const orderDir = orderMatch[2]?.toUpperCase() === 'DESC' ? -1 : 1;
                  results.sort((a, b) => {
                    const valA = a[orderCol] || '';
                    const valB = b[orderCol] || '';
                    if (valA < valB) return -1 * orderDir;
                    if (valA > valB) return 1 * orderDir;
                    return 0;
                  });
                }
                
                return results;
              }

              // 字面量恒等式 WHERE（如 1=1）视为无条件条件，返回全部（含排序）
              const literalWhere = sql.match(/WHERE\s+([\s\S]+?)(?:ORDER|LIMIT|$)/i);
              if (literalWhere && /^[\d\s]+\s*=\s*[\d\s]+$/.test(literalWhere[1].trim())) {
                let results = tables[tableName] || [];
                const orderMatch = sql.match(/ORDER\s+BY\s+(\w+)\s*(ASC|DESC)?/i);
                if (orderMatch) {
                  const orderCol = orderMatch[1];
                  const orderDir = orderMatch[2]?.toUpperCase() === 'DESC' ? -1 : 1;
                  results = [...results].sort((a, b) => {
                    const valA = a[orderCol] || '';
                    const valB = b[orderCol] || '';
                    if (valA < valB) return -1 * orderDir;
                    if (valA > valB) return 1 * orderDir;
                    return 0;
                  });
                }
                return results;
              }

              const whereMatch = sql.match(/WHERE\s+(\w+)\s*=\s*['"]?([^'"\s]+)['"]?/i);
              if (whereMatch) {
                const [, col, val] = whereMatch;
                return tables[tableName]?.filter(row => row[col] == val) || [];
              }
              
              return tables[tableName] || [];
            }
            if (sql.includes('SELECT key, value')) {
              return tables.sys_config || [];
            }
            return [];
          }
        };
      },
      
      run: function(sql, params) {
        const stmt = this.prepare(sql);
        return stmt.run(params);
      },
      
      get: function(sql, params) {
        const stmt = this.prepare(sql);
        return stmt.get(params);
      },
      
      all: function(sql, params) {
        const stmt = this.prepare(sql);
        return stmt.all(params);
      },
      
      close: function() {
        if (persistTimer) clearTimeout(persistTimer);
        persist();
        logger.info('数据库连接已关闭');
      },

      /**
       * 内部辅助：按条件删除行（shim 能力补充，供数据保留/归档等服务使用；
       * 切换真实数据库后以 SQL: DELETE FROM t WHERE ... 替代）
       */
      _deleteRows: function(table, predicate) {
        if (!tables[table]) return 0;
        const before = tables[table].length;
        tables[table] = tables[table].filter(row => !predicate(row));
        const deleted = before - tables[table].length;
        if (deleted > 0) schedulePersist();
        return deleted;
      },

      /** 内部辅助：直接访问原始表数组（供迁移/统计等场景使用） */
      _rawTable: function(table) {
        return tables[table];
      },

      /** 立即落盘 */
      saveDb: function() {
        persist();
      }
    };
    logger.info(`内存数据库已初始化${persistEnabled ? `（持久化到 ${DB_PATH}）` : '（持久化已禁用）'}`);
  }
  return db;
}

function closeDb() {
  if (db) {
    db.close();
    db = null;
  }
}

module.exports = { getDb, closeDb, resetForTest, persist, saveDb: persist };