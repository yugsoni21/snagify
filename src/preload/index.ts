import { contextBridge, ipcRenderer } from 'electron'
import { electronAPI } from '@electron-toolkit/preload'
import type { ScanProgress } from './index.d'

const api = {
  selectFolder: (): Promise<string | null> =>
    ipcRenderer.invoke('select-folder'),

  getFolderStats: (folderPath: string) =>
    ipcRenderer.invoke('get-folder-stats', folderPath),

  runScan: (folderPath: string) =>
    ipcRenderer.invoke('run-scan', folderPath),

  cancelScan: (): Promise<void> =>
    ipcRenderer.invoke('cancel-scan'),

  onScanProgress: (callback: (progress: ScanProgress) => void): (() => void) => {
    const listener = (_: Electron.IpcRendererEvent, progress: ScanProgress): void => {
      callback(progress)
    }
    ipcRenderer.on('scan-progress', listener)
    return () => {
      ipcRenderer.removeListener('scan-progress', listener)
    }
  },

  saveApiKey: (key: string): Promise<void> =>
    ipcRenderer.invoke('save-api-key', key),

  getApiKeyStatus: (): Promise<boolean> =>
    ipcRenderer.invoke('get-api-key-status'),

  getAiProvider: () => ipcRenderer.invoke('get-ai-provider'),
  setAiProvider: (settings: { provider: string; model?: string; baseUrl?: string }): Promise<void> =>
    ipcRenderer.invoke('set-ai-provider', settings),
  testAiProvider: () => ipcRenderer.invoke('test-ai-provider'),
  detectProviderFromKey: (key: string) => ipcRenderer.invoke('detect-provider-from-key', key),

  analyzeFindings: (semgrepFindings: unknown[], gitleaksFindings: unknown[], osvFindings?: unknown[]) =>
    ipcRenderer.invoke('analyze-findings', semgrepFindings, gitleaksFindings, osvFindings ?? []),

  generateFix: (folderPath: string, finding: unknown) =>
    ipcRenderer.invoke('generate-fix', folderPath, finding),

  applyFix: (folderPath: string, patch: unknown) =>
    ipcRenderer.invoke('apply-fix', folderPath, patch),

  revertFix: (backupId: string): Promise<void> =>
    ipcRenderer.invoke('revert-fix', backupId),

  suppressFinding: (folderPath: string, finding: unknown) =>
    ipcRenderer.invoke('suppress-finding', folderPath, finding),

  unsuppressFinding: (folderPath: string, key: string) =>
    ipcRenderer.invoke('unsuppress-finding', folderPath, key),

  getSuppressions: (folderPath: string) =>
    ipcRenderer.invoke('get-suppressions', folderPath),

  getHookStatus: (folderPath: string): Promise<boolean> =>
    ipcRenderer.invoke('get-hook-status', folderPath),

  installHook: (folderPath: string, minScore: number): Promise<void> =>
    ipcRenderer.invoke('install-hook', folderPath, minScore),

  uninstallHook: (folderPath: string): Promise<void> =>
    ipcRenderer.invoke('uninstall-hook', folderPath),

  validateLicense: (key: string) =>
    ipcRenderer.invoke('validate-license', key),

  authAvailable: (): Promise<boolean> =>
    ipcRenderer.invoke('auth-available'),

  authSignUp: (email: string, password: string) =>
    ipcRenderer.invoke('auth-sign-up', email, password),

  authSignIn: (email: string, password: string) =>
    ipcRenderer.invoke('auth-sign-in', email, password),

  authSignOut: (): Promise<void> =>
    ipcRenderer.invoke('auth-sign-out'),

  authGetSession: () =>
    ipcRenderer.invoke('auth-get-session'),

  getLicenseStatus: () =>
    ipcRenderer.invoke('get-license-status'),

  getMachineId: (): Promise<string> =>
    ipcRenderer.invoke('get-machine-id'),

  deactivateLicense: (): Promise<void> =>
    ipcRenderer.invoke('deactivate-license'),

  getScanHistory: () =>
    ipcRenderer.invoke('get-scan-history'),

  getScanById: (id: string) =>
    ipcRenderer.invoke('get-scan-by-id', id),

  deleteScan: (id: string): Promise<void> =>
    ipcRenderer.invoke('delete-scan', id),

  savePdfReport: (filename: string, data: Uint8Array): Promise<string> =>
    ipcRenderer.invoke('save-pdf-report', filename, data),

  getAppVersion: (): Promise<string> =>
    ipcRenderer.invoke('get-app-version'),

  onNavigateTo: (callback: (page: string) => void): (() => void) => {
    const listener = (_: Electron.IpcRendererEvent, page: string): void => callback(page)
    ipcRenderer.on('navigate-to', listener)
    return () => ipcRenderer.removeListener('navigate-to', listener)
  }
}

if (process.contextIsolated) {
  try {
    contextBridge.exposeInMainWorld('electron', electronAPI)
    contextBridge.exposeInMainWorld('api', api)
  } catch (error) {
    console.error(error)
  }
} else {
  // @ts-ignore (define in dts)
  window.electron = electronAPI
  // @ts-ignore (define in dts)
  window.api = api
}
