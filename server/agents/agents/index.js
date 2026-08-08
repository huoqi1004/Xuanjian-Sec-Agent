/** 注册全部业务 Agent */
const { registerAgent } = require('../registry');
const PlannerAgent = require('./plannerAgent');
const ExecutorAgent = require('./executorAgent');
const AnalystAgent = require('./analystAgent');
const IntelAgent = require('./intelAgent');
const ReporterAgent = require('./reporterAgent');
const ScanAgent = require('./scanAgent');
const { DefenseAgent } = require('./defenseAgent');

function registerAgents() {
  registerAgent(PlannerAgent);
  registerAgent(ExecutorAgent);
  registerAgent(AnalystAgent);
  registerAgent(IntelAgent);
  registerAgent(ReporterAgent);
  registerAgent(ScanAgent);
  registerAgent(DefenseAgent);
}
module.exports = { registerAgents };
