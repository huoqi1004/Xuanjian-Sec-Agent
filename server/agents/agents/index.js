/** 注册全部业务 Agent（幂等：重复调用直接跳过） */
const { registerAgent } = require('../registry');
const PlannerAgent = require('./plannerAgent');
const ExecutorAgent = require('./executorAgent');
const AnalystAgent = require('./analystAgent');
const IntelAgent = require('./intelAgent');
const ReporterAgent = require('./reporterAgent');
const ScanAgent = require('./scanAgent');
const { DefenseAgent } = require('./defenseAgent');

let registered = false;
function registerAgents() {
  if (registered) return;
  registerAgent(PlannerAgent);
  registerAgent(ExecutorAgent);
  registerAgent(AnalystAgent);
  registerAgent(IntelAgent);
  registerAgent(ReporterAgent);
  registerAgent(ScanAgent);
  registerAgent(DefenseAgent);
  registered = true;
}
module.exports = { registerAgents };
