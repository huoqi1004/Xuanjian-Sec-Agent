// 病毒查杀流程演示入口（CLI）
// 运行方式: node scripts/run-virus-scan-demo.js
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../.env') });
const { runDemo } = require('./virus-scan-demo');

runDemo({ verbose: true }).catch(err => {
  console.error('Demo failed:', err.message);
  console.error(err.stack);
  process.exit(1);
});
