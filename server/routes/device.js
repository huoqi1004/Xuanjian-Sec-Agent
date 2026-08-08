const express = require('express');
const { authMiddleware } = require('../middleware/auth');
const { checkPermission, adminOnly } = require('../middleware/rbac');
const { auditLog } = require('../middleware/audit');
const { success, fail, asyncHandler } = require('../utils/helpers');
const deviceService = require('../services/deviceService');

const router = express.Router();

router.use(authMiddleware);

/**
 * GET /api/device/list - 获取设备列表
 */
router.get('/list', checkPermission('GET'), asyncHandler(async (req, res) => {
  const { page = 1, pageSize = 10, online_status } = req.query;
  const devices = deviceService.getDevices(parseInt(page), parseInt(pageSize), online_status);
  return success(res, devices);
}));

/**
 * POST /api/device/register - 设备注册
 */
router.post('/register', auditLog('device_register'), asyncHandler(async (req, res) => {
  const { device_id, device_type, ip } = req.body;

  if (!device_id) {
    return fail(res, '设备ID不能为空');
  }

  const device = deviceService.registerDevice(device_id, device_type, ip);
  return success(res, device, '设备注册成功');
}));

/**
 * GET /api/device/:id/status - 获取设备状态
 */
router.get('/:id/status', checkPermission('GET'), asyncHandler(async (req, res) => {
  const { id } = req.params;
  const status = deviceService.getDeviceStatus(id);
  if (!status) {
    return fail(res, '设备不存在');
  }
  return success(res, status);
}));

/**
 * POST /api/device/:id/command - 下发指令
 */
router.post('/:id/command', checkPermission('POST'), auditLog('device_command'), asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { command, params } = req.body;

  if (!command) {
    return fail(res, '指令不能为空');
  }

  const result = deviceService.sendCommand(id, command, params);
  return success(res, result, '指令已下发');
}));

/**
 * GET /api/device/:id/commands - 获取指令历史
 */
router.get('/:id/commands', checkPermission('GET'), asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { page = 1, pageSize = 10 } = req.query;
  const commands = deviceService.getCommandHistory(id, parseInt(page), parseInt(pageSize));
  return success(res, commands);
}));

/**
 * POST /api/device/:id/unregister - 注销设备
 */
router.post('/:id/unregister', adminOnly, auditLog('device_unregister'), asyncHandler(async (req, res) => {
  const deviceService = require('../services/deviceService');
  const result = deviceService.unregisterDevice(req.params.id);
  if (!result) return fail(res, '设备不存在');
  return success(res, null, '设备已注销');
}));

module.exports = router;
