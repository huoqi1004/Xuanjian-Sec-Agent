/** 内置工具一次性注册入口 */
const { resetTools } = require('./registry');
const { registerIntelTools } = require('./intelTools');
const { registerQueryTools } = require('./queryTools');
const { registerActionTools } = require('./actionTools');
const { registerDefenseTools } = require('./defenseTools');

let registered = false;
function registerBuiltinTools({ force = false } = {}) {
  if (registered && !force) return;
  if (force) resetTools();
  registerIntelTools();
  registerQueryTools();
  registerActionTools();
  registerDefenseTools();
  registered = true;
}

module.exports = { registerBuiltinTools };
