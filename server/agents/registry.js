/** Agent 注册中心：name → 构造类，供编排器路由 */
const agents = new Map();

function registerAgent(AgentClass, { override = false } = {}) {
  const name = new AgentClass().name;
  if (!override && agents.has(name)) throw new Error(`Agent 已注册: ${name}`);
  agents.set(name, AgentClass);
  return name;
}

function getAgent(name) {
  const Cls = agents.get(name);
  if (!Cls) throw new Error(`未知 Agent: ${name}`);
  return new Cls();
}

function listAgents() {
  return [...agents.entries()].map(([name, Cls]) => {
    const inst = new Cls();
    return { name, capability: inst.capability };
  });
}

module.exports = { registerAgent, getAgent, listAgents };
