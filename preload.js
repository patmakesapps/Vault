/**
 * preload.js — Security bridge
 *
 * This file runs in a privileged context and exposes a limited,
 * safe API to the renderer (React). The renderer can ONLY call
 * these specific functions — it has no direct access to Node.js.
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('vaultAPI', {
  // Export vault to a file (opens save dialog)
  exportVault: (encryptedData) =>
    ipcRenderer.invoke('vault:export', encryptedData),

  // Import vault from a file (opens open dialog)
  importVault: () =>
    ipcRenderer.invoke('vault:import'),

  // Save a timestamped backup to the auto-backup folder
  saveBackup: (encryptedData) =>
    ipcRenderer.invoke('vault:save-backup', encryptedData),

  // Let the user choose an auto-backup folder
  setBackupDir: () =>
    ipcRenderer.invoke('vault:set-backup-dir'),

  // Get the currently configured backup folder path
  getBackupDir: () =>
    ipcRenderer.invoke('vault:get-backup-dir'),
});
