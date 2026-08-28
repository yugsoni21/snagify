import { useState, useCallback, useEffect, useRef, Component } from 'react'
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid
} from 'recharts'
import { jsPDF } from 'jspdf'
import type {
  TreeNode, FolderStats, ScanProgress, ScanResult,
  AnalysisResult, AIFinding, LicenseStatus, ScanHistoryEntry, FixPatch, SuppressedFinding, AuthSessionInfo,
  ScalabilityAssessment, AiProviderInfo
} from '../../preload/index.d'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type NavItem = 'dashboard' | 'new-scan' | 'history' | 'settings'
type ScanPhase = 'idle' | 'loading' | 'ready' | 'scanning' | 'done'
type AppState = 'checking' | 'unlicensed' | 'licensed'

interface NavEntry { id: NavItem; label: string; icon: React.ReactNode }

// ---------------------------------------------------------------------------
// Color / config helpers
// ---------------------------------------------------------------------------

const LANG_COLORS: Record<string, string> = {
  TypeScript: '#3b82f6', JavaScript: '#eab308', Python: '#f97316',
  Go: '#06b6d4', Rust: '#ef4444', Java: '#ca8a04', Kotlin: '#a855f7',
  Swift: '#f43f5e', C: '#6b7280', 'C++': '#ec4899', 'C/C++': '#6b7280',
  'C#': '#22c55e', Ruby: '#dc2626', PHP: '#6366f1', Solidity: '#d97706',
  Shell: '#84cc16', HTML: '#f97316', CSS: '#7c3aed', SCSS: '#db2777',
  Sass: '#db2777', Less: '#1d4ed8', YAML: '#94a3b8', JSON: '#64748b',
  TOML: '#94a3b8', Vue: '#22c55e', Svelte: '#ff3e00', Dart: '#14b8a6',
  Terraform: '#8b5cf6', Docker: '#3b82f6', R: '#3b82f6', Lua: '#6366f1',
  Elixir: '#a855f7', Clojure: '#22c55e', Scala: '#dc2626', Haskell: '#a855f7', OCaml: '#f97316'
}

const FILE_EXT_COLORS: Record<string, string> = {
  '.ts': '#3b82f6', '.tsx': '#3b82f6', '.js': '#eab308', '.jsx': '#eab308',
  '.mjs': '#eab308', '.py': '#f97316', '.go': '#06b6d4', '.rs': '#ef4444',
  '.json': '#64748b', '.yaml': '#94a3b8', '.yml': '#94a3b8', '.toml': '#94a3b8',
  '.md': '#94a3b8', '.css': '#7c3aed', '.scss': '#db2777', '.html': '#f97316',
  '.sh': '#84cc16', '.bash': '#84cc16', '.tf': '#8b5cf6', '.sol': '#d97706',
  '.vue': '#22c55e', '.svelte': '#ff3e00'
}

const getLangColor = (lang: string): string => LANG_COLORS[lang] ?? '#6b7280'
const getFileColor = (name: string): string => {
  const ext = '.' + (name.split('.').pop()?.toLowerCase() ?? '')
  return FILE_EXT_COLORS[ext] ?? '#3a3a3a'
}

const SEVERITY_CONFIG = {
  critical: { label: 'Critical', color: '#ef4444', bg: 'rgba(239,68,68,0.1)',   border: 'rgba(239,68,68,0.2)' },
  high:     { label: 'High',     color: '#f97316', bg: 'rgba(249,115,22,0.1)',  border: 'rgba(249,115,22,0.2)' },
  medium:   { label: 'Medium',   color: '#eab308', bg: 'rgba(234,179,8,0.1)',   border: 'rgba(234,179,8,0.2)' },
  low:      { label: 'Low',      color: '#6b7280', bg: 'rgba(107,114,128,0.1)', border: 'rgba(107,114,128,0.2)' }
} as const
type Severity = keyof typeof SEVERITY_CONFIG

function getScoreColor(score: number): string {
  if (score >= 71) return '#16a34a'
  if (score >= 41) return '#eab308'
  return '#ef4444'
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
}
function formatDateShort(iso: string): string {
  return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
}
function formatDateTime(iso: string): string {
  const d = new Date(iso)
  return formatDate(iso) + ' ' + d.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' })
}
function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60_000)
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  const days = Math.floor(hrs / 24)
  return `${days}d ago`
}

// ---------------------------------------------------------------------------
// Scan step config
// ---------------------------------------------------------------------------

const SCAN_STEPS = [
  { id: 'init',     label: 'Initializing' },
  { id: 'semgrep',  label: 'Running security scan' },
  { id: 'gitleaks', label: 'Detecting secrets' },
  { id: 'osv',      label: 'Checking dependencies for CVEs' },
  { id: 'ai',       label: 'Analyzing with AI' },
  { id: 'scaling',  label: 'Assessing scalability under load' }
]

function getActiveStepIndex(step: string | undefined): number {
  if (!step) return -1
  if (step === 'done') return SCAN_STEPS.length
  if (step === 'init') return 0
  if (step.startsWith('semgrep')) return 1
  if (step.startsWith('gitleaks')) return 2
  if (step.startsWith('osv')) return 3
  if (step.startsWith('scaling')) return 5
  if (step.startsWith('ai')) return 4
  return -1
}
type StepDisplayState = 'pending' | 'active' | 'done' | 'error' | 'skipped'
function getStepDisplayState(stepIdx: number, activeIdx: number, currentStep: string | undefined): StepDisplayState {
  if (activeIdx >= SCAN_STEPS.length) return 'done'
  if (stepIdx < activeIdx) return 'done'
  if (stepIdx === activeIdx) {
    if (currentStep?.endsWith('-error')) return 'error'
    if (currentStep?.endsWith('-skip')) return 'skipped'
    return 'active'
  }
  return 'pending'
}

// ---------------------------------------------------------------------------
// Icons
// ---------------------------------------------------------------------------

function IconGrid(): React.ReactElement {
  return <svg width="15" height="15" viewBox="0 0 15 15" fill="none"><path d="M1 2.5C1 2.22386 1.22386 2 1.5 2H5.5C5.77614 2 6 2.22386 6 2.5V6.5C6 6.77614 5.77614 7 5.5 7H1.5C1.22386 7 1 6.77614 1 6.5V2.5ZM9 2.5C9 2.22386 9.22386 2 9.5 2H13.5C13.7761 2 14 2.22386 14 2.5V6.5C14 6.77614 13.7761 7 13.5 7H9.5C9.22386 7 9 6.77614 9 6.5V2.5ZM1 9.5C1 9.22386 1.22386 9 1.5 9H5.5C5.77614 9 6 9.22386 6 9.5V13.5C6 13.7761 5.77614 14 5.5 14H1.5C1.22386 14 1 13.7761 1 13.5V9.5ZM9 9.5C9 9.22386 9.22386 9 9.5 9H13.5C13.7761 9 14 9.22386 14 9.5V13.5C14 13.7761 13.7761 14 13.5 14H9.5C9.22386 14 9 13.7761 9 13.5V9.5Z" fill="currentColor" fillRule="evenodd" clipRule="evenodd" /></svg>
}
function IconScan(): React.ReactElement {
  return <svg width="15" height="15" viewBox="0 0 15 15" fill="none"><path d="M1.5 1C1.22386 1 1 1.22386 1 1.5V4.5C1 4.77614 1.22386 5 1.5 5C1.77614 5 2 4.77614 2 4.5V2H4.5C4.77614 2 5 1.77614 5 1.5C5 1.22386 4.77614 1 4.5 1H1.5ZM10 1.5C10 1.22386 10.2239 1 10.5 1H13.5C13.7761 1 14 1.22386 14 1.5V4.5C14 4.77614 13.7761 5 13.5 5C13.2239 5 13 4.77614 13 4.5V2H10.5C10.2239 2 10 1.77614 10 1.5ZM1 10.5C1 10.2239 1.22386 10 1.5 10C1.77614 10 2 10.2239 2 10.5V13H4.5C4.77614 13 5 13.2239 5 13.5C5 13.7761 4.77614 14 4.5 14H1.5C1.22386 14 1 13.7761 1 13.5V10.5ZM13.5 10C13.7761 10 14 10.2239 14 10.5V13.5C14 13.7761 13.7761 14 13.5 14H10.5C10.2239 14 10 13.7761 10 13.5C10 13.2239 10.2239 13 10.5 13H13V10.5C13 10.2239 13.2239 10 13.5 10ZM4 7.5C4 7.22386 4.22386 7 4.5 7H10.5C10.7761 7 11 7.22386 11 7.5C11 7.77614 10.7761 8 10.5 8H4.5C4.22386 8 4 7.77614 4 7.5Z" fill="currentColor" fillRule="evenodd" clipRule="evenodd" /></svg>
}
function IconHistory(): React.ReactElement {
  return <svg width="15" height="15" viewBox="0 0 15 15" fill="none"><path d="M1.84998 7.49998C1.84998 4.66458 4.05979 1.84998 7.49998 1.84998C10.2783 1.84998 11.6515 3.9064 12.2367 5H10.5C10.2239 5 10 5.22386 10 5.5C10 5.77614 10.2239 6 10.5 6H13.5C13.7761 6 14 5.77614 14 5.5V2.5C14 2.22386 13.7761 2 13.5 2C13.2239 2 13 2.22386 13 2.5V4.31318C12.2955 3.07126 10.6659 0.849976 7.49998 0.849976C3.43716 0.849976 0.849976 4.18537 0.849976 7.49998C0.849976 10.8146 3.43716 14.15 7.49998 14.15C9.44382 14.15 11.0622 13.3808 12.2145 12.2084C12.8315 11.5806 13.3133 10.8376 13.6418 10.0429C13.7469 9.78575 13.6251 9.49309 13.368 9.38798C13.1108 9.28287 12.8182 9.40472 12.7131 9.66185C12.4334 10.3394 12.0126 10.9765 11.4753 11.5211C10.4943 12.5127 9.14469 13.15 7.49998 13.15C4.05979 13.15 1.84998 10.3354 1.84998 7.49998ZM7.49998 4.09998C7.22383 4.09998 6.99998 4.32383 6.99998 4.59998V7.49998C6.99998 7.63259 7.05264 7.75977 7.14641 7.85354L9.14641 9.85354C9.34167 10.0488 9.65826 10.0488 9.85352 9.85354C10.0488 9.65828 10.0488 9.34169 9.85352 9.14643L7.99998 7.29289V4.59998C7.99998 4.32383 7.77612 4.09998 7.49998 4.09998Z" fill="currentColor" fillRule="evenodd" clipRule="evenodd" /></svg>
}
function IconSettings(): React.ReactElement {
  return <svg width="15" height="15" viewBox="0 0 15 15" fill="none"><path d="M7.07095 0.899951C6.67391 0.899951 6.25587 1.15235 6.17686 1.66503L6.05315 2.42835C5.87687 3.5259 4.57268 4.0604 3.65316 3.40283L3.03093 2.98036C2.61519 2.69762 2.11285 2.73426 1.82866 3.01845C1.54447 3.30264 1.50783 3.80498 1.79057 4.22072L2.21304 4.84295C2.87061 5.76247 2.33616 7.0667 1.23861 7.24297L0.475286 7.36669C-0.0373873 7.4457 -0.289792 7.86374 -0.289792 8.26078C-0.289792 8.65782 -0.0373873 9.07586 0.475286 9.15487L1.23861 9.27859C2.33616 9.45486 2.87061 10.7591 2.21304 11.6786L1.79057 12.3008C1.50783 12.7166 1.54447 13.2189 1.82866 13.5031C2.11285 13.7873 2.61519 13.8239 3.03093 13.5412L3.65316 13.1187C4.57268 12.4612 5.87687 12.9956 6.05315 14.0932L6.17686 14.8565C6.25587 15.3692 6.67391 15.6216 7.07095 15.6216C7.46799 15.6216 7.88603 15.3692 7.96504 14.8565L8.08875 14.0932C8.26503 12.9956 9.56922 12.4612 10.4887 13.1187L11.111 13.5412C11.5267 13.8239 12.0291 13.7873 12.3132 13.5031C12.5974 13.2189 12.6341 12.7166 12.3513 12.3008L11.9289 11.6786C11.2713 10.7591 11.8057 9.45486 12.9033 9.27859L13.6666 9.15487C14.1793 9.07586 14.4317 8.65782 14.4317 8.26078C14.4317 7.86374 14.1793 7.4457 13.6666 7.36669L12.9033 7.24297C11.8057 7.0667 11.2713 5.76247 11.9289 4.84295L12.3513 4.22072C12.6341 3.80498 12.5974 3.30264 12.3132 3.01845C12.0291 2.73426 11.5267 2.69762 11.111 2.98036L10.4887 3.40283C9.56922 4.0604 8.26503 3.5259 8.08875 2.42835L7.96504 1.66503C7.88603 1.15235 7.46799 0.899951 7.07095 0.899951ZM7.07095 5.46078C5.64452 5.46078 4.48848 6.61682 4.48848 8.04325C4.48848 9.46968 5.64452 10.6257 7.07095 10.6257C8.49738 10.6257 9.65342 9.46968 9.65342 8.04325C9.65342 6.61682 8.49738 5.46078 7.07095 5.46078ZM5.48848 8.04325C5.48848 7.16905 6.19675 6.46078 7.07095 6.46078C7.94515 6.46078 8.65342 7.16905 8.65342 8.04325C8.65342 8.91745 7.94515 9.62572 7.07095 9.62572C6.19675 9.62572 5.48848 8.91745 5.48848 8.04325Z" fill="currentColor" fillRule="evenodd" clipRule="evenodd" /></svg>
}
function IconFolder({ size = 24 }: { size?: number }): React.ReactElement {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none"><path d="M3 7C3 5.89543 3.89543 5 5 5H9.58579C9.851 5 10.1054 5.10536 10.2929 5.29289L11.7071 6.70711C11.8946 6.89464 12.149 7 12.4142 7H19C20.1046 7 21 7.89543 21 9V17C21 18.1046 20.1046 19 19 19H5C3.89543 19 3 18.1046 3 17V7Z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>
}
function IconChevronRight(): React.ReactElement {
  return <svg width="10" height="10" viewBox="0 0 15 15" fill="none"><path d="M6.1584 3.13508C6.35985 2.94621 6.67627 2.95642 6.86514 3.15788L10.3651 6.85788C10.5537 7.05933 10.5537 7.37887 10.3651 7.58033L6.86514 11.2803C6.67627 11.4818 6.35985 11.492 6.1584 11.3031C5.95694 11.1142 5.94673 10.7978 6.1356 10.5964L9.28265 7.21910L6.1356 3.84178C5.94673 3.64033 5.95694 3.32391 6.1584 3.13508Z" fill="currentColor" fillRule="evenodd" clipRule="evenodd" /></svg>
}
function IconFile(): React.ReactElement {
  return <svg width="11" height="11" viewBox="0 0 15 15" fill="none"><path d="M3.5 2C3.22386 2 3 2.22386 3 2.5V12.5C3 12.7761 3.22386 13 3.5 13H11.5C11.7761 13 12 12.7761 12 12.5V6H8.5C8.22386 6 8 5.77614 8 5.5V2H3.5ZM9 2.70711L11.2929 5H9V2.70711ZM2 2.5C2 1.67157 2.67157 1 3.5 1H8.5C8.63261 1 8.75979 1.05268 8.85355 1.14645L12.8536 5.14645C12.9473 5.24021 13 5.36739 13 5.5V12.5C13 13.3284 12.3284 14 11.5 14H3.5C2.67157 14 2 13.3284 2 12.5V2.5Z" fill="currentColor" fillRule="evenodd" clipRule="evenodd" /></svg>
}
function IconPlay(): React.ReactElement {
  return <svg width="14" height="14" viewBox="0 0 15 15" fill="none"><path d="M3.24182 2.32181C3.3919 2.23132 3.5784 2.22601 3.73338 2.30781L12.7334 7.05781C12.8974 7.14436 13 7.31457 13 7.5C13 7.68543 12.8974 7.85564 12.7334 7.94219L3.73338 12.6922C3.5784 12.774 3.3919 12.7687 3.24182 12.6782C3.09175 12.5877 3 12.4252 3 12.25V2.75C3 2.57476 3.09175 2.4123 3.24182 2.32181ZM4 3.57925V11.4207L11.4288 7.5L4 3.57925Z" fill="currentColor" fillRule="evenodd" clipRule="evenodd" /></svg>
}
function IconCheck(): React.ReactElement {
  return <svg width="11" height="11" viewBox="0 0 15 15" fill="none"><path d="M11.4669 3.72684C11.7558 3.91574 11.8369 4.30308 11.648 4.59198L7.39799 11.092C7.29783 11.2452 7.13556 11.3467 6.95402 11.3699C6.77247 11.3931 6.58989 11.3355 6.45446 11.2124L3.70446 8.71241C3.44905 8.48022 3.43023 8.08494 3.66242 7.82953C3.89461 7.57412 4.28989 7.55529 4.5453 7.78749L6.75292 9.79441L10.6018 3.90792C10.7907 3.61902 11.178 3.53795 11.4669 3.72684Z" fill="currentColor" fillRule="evenodd" clipRule="evenodd" /></svg>
}
function IconX(): React.ReactElement {
  return <svg width="13" height="13" viewBox="0 0 15 15" fill="none"><path d="M11.7816 4.03157C12.0062 3.80702 12.0062 3.44295 11.7816 3.2184C11.5571 2.99385 11.193 2.99385 10.9685 3.2184L7.50005 6.68682L4.03164 3.2184C3.80708 2.99385 3.44301 2.99385 3.21846 3.2184C2.99391 3.44295 2.99391 3.80702 3.21846 4.03157L6.68688 7.49999L3.21846 10.9684C2.99391 11.193 2.99391 11.557 3.21846 11.7816C3.44301 12.0061 3.80708 12.0061 4.03164 11.7816L7.50005 8.31316L10.9685 11.7816C11.193 12.0061 11.5571 12.0061 11.7816 11.7816C12.0062 11.557 12.0062 11.193 11.7816 10.9684L8.31322 7.49999L11.7816 4.03157Z" fill="currentColor" fillRule="evenodd" clipRule="evenodd" /></svg>
}
function IconShield(): React.ReactElement {
  return <svg width="18" height="18" viewBox="0 0 24 24" fill="none"><path d="M12 2L4 6V12C4 16.4183 7.58172 20.4 12 22C16.4183 20.4 20 16.4183 20 12V6L12 2Z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>
}
function IconKey(): React.ReactElement {
  return <svg width="18" height="18" viewBox="0 0 24 24" fill="none"><circle cx="8" cy="15" r="4" stroke="currentColor" strokeWidth="1.5" /><path d="M12 11L21 2M19 4L21 6M17 6L19 8" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>
}
function IconLock(): React.ReactElement {
  return <svg width="13" height="13" viewBox="0 0 15 15" fill="none"><path d="M5 4.63601C5 3.76031 5.24219 3.1054 5.64323 2.67357C6.03934 2.24705 6.64582 1.9783 7.5014 1.9783C8.35745 1.9783 8.96306 2.24652 9.35823 2.67208C9.75838 3.10299 10 3.75708 10 4.63325V5H5V4.63601ZM4 5V4.63601C4 3.58148 4.29339 2.65754 4.91049 1.99307C5.53252 1.32329 6.42675 1 7.5014 1C8.57583 1 9.46952 1.32233 10.0915 1.99129C10.7086 2.65502 11 3.57896 11 4.63325V5H12C12.5523 5 13 5.44772 13 6V13C13 13.5523 12.5523 14 12 14H3C2.44772 14 2 13.5523 2 13V6C2 5.44772 2.44772 5 3 5H4ZM3 6V13H12V6H3Z" fill="currentColor" fillRule="evenodd" clipRule="evenodd" /></svg>
}
function IconChevronDown(): React.ReactElement {
  return <svg width="12" height="12" viewBox="0 0 15 15" fill="none"><path d="M3.13523 6.15803C3.3241 5.95657 3.64052 5.94637 3.84197 6.13523L7.5 9.56464L11.158 6.13523C11.3595 5.94637 11.6759 5.95657 11.8648 6.15803C12.0536 6.35949 12.0434 6.67591 11.842 6.86477L7.84197 10.6148C7.64964 10.7951 7.35036 10.7951 7.15803 10.6148L3.15803 6.86477C2.95657 6.67591 2.94637 6.35949 3.13523 6.15803Z" fill="currentColor" fillRule="evenodd" clipRule="evenodd" /></svg>
}
function IconTrash(): React.ReactElement {
  return <svg width="13" height="13" viewBox="0 0 15 15" fill="none"><path d="M5.5 1C5.22386 1 5 1.22386 5 1.5C5 1.77614 5.22386 2 5.5 2H9.5C9.77614 2 10 1.77614 10 1.5C10 1.22386 9.77614 1 9.5 1H5.5ZM3 3.5C3 3.22386 3.22386 3 3.5 3H11.5C11.7761 3 12 3.22386 12 3.5C12 3.77614 11.7761 4 11.5 4H3.5C3.22386 4 3 3.77614 3 3.5ZM4.09989 5.00002C4.12989 5.00002 4.1598 5.00146 4.18959 5.00433L4.68198 12.0556C4.72158 12.6178 5.18398 13 5.74762 13H9.25238C9.81602 13 10.2784 12.6178 10.318 12.0556L10.8104 5.00433C10.8402 5.00146 10.8701 5.00002 10.9001 5.00002L4.09989 5.00002Z" fill="currentColor" fillRule="evenodd" clipRule="evenodd" /></svg>
}
function IconArrowLeft(): React.ReactElement {
  return <svg width="14" height="14" viewBox="0 0 15 15" fill="none"><path d="M6.85355 3.14645C7.04882 3.34171 7.04882 3.65829 6.85355 3.85355L3.70711 7H12.5C12.7761 7 13 7.22386 13 7.5C13 7.77614 12.7761 8 12.5 8H3.70711L6.85355 11.1464C7.04882 11.3417 7.04882 11.6583 6.85355 11.8536C6.65829 12.0488 6.34171 12.0488 6.14645 11.8536L2.14645 7.85355C1.95118 7.65829 1.95118 7.34171 2.14645 7.14645L6.14645 3.14645C6.34171 2.95118 6.65829 2.95118 6.85355 3.14645Z" fill="currentColor" fillRule="evenodd" clipRule="evenodd" /></svg>
}
function IconDownload(): React.ReactElement {
  return <svg width="13" height="13" viewBox="0 0 15 15" fill="none"><path d="M7.50005 1.04999C7.74858 1.04999 7.95005 1.25146 7.95005 1.49999V8.41359L10.1819 6.18179C10.3576 6.00605 10.6425 6.00605 10.8182 6.18179C10.9939 6.35753 10.9939 6.64247 10.8182 6.81821L7.81825 9.81821C7.64251 9.99395 7.35757 9.99395 7.18183 9.81821L4.18183 6.81821C4.00609 6.64247 4.00609 6.35753 4.18183 6.18179C4.35757 6.00605 4.64251 6.00605 4.81825 6.18179L7.05005 8.41359V1.49999C7.05005 1.25146 7.25152 1.04999 7.50005 1.04999ZM2.5 10C2.77614 10 3 10.2239 3 10.5V12C3 12.5539 3.44565 13 3.99635 13H11.0012C11.5529 13 12 12.5528 12 12V10.5C12 10.2239 12.2239 10 12.5 10C12.7761 10 13 10.2239 13 10.5V12C13 13.1041 12.1062 14 11.0012 14H3.99635C2.89019 14 2 13.103 2 12V10.5C2 10.2239 2.22386 10 2.5 10Z" fill="currentColor" fillRule="evenodd" clipRule="evenodd" /></svg>
}
function IconCopy(): React.ReactElement {
  return <svg width="13" height="13" viewBox="0 0 15 15" fill="none"><path d="M1 9.50006C1 10.3285 1.67157 11.0001 2.5 11.0001H4L4 10.0001H2.5C2.22386 10.0001 2 9.7762 2 9.50006L2 2.50006C2 2.22392 2.22386 2.00006 2.5 2.00006L9.5 2.00006C9.77614 2.00006 10 2.22392 10 2.50006V4.00002H5.5C4.67158 4.00002 4 4.67159 4 5.50002V12.5C4 13.3284 4.67158 14 5.5 14H12.5C13.3284 14 14 13.3284 14 12.5V5.50002C14 4.67159 13.3284 4.00002 12.5 4.00002H11V2.50006C11 1.67163 10.3284 1.00006 9.5 1.00006H2.5C1.67157 1.00006 1 1.67163 1 2.50006V9.50006ZM5 5.50002C5 5.22388 5.22386 5.00002 5.5 5.00002H12.5C12.7761 5.00002 13 5.22388 13 5.50002V12.5C13 12.7762 12.7761 13 12.5 13H5.5C5.22386 13 5 12.7762 5 12.5V5.50002Z" fill="currentColor" fillRule="evenodd" clipRule="evenodd" /></svg>
}
function IconInfo(): React.ReactElement {
  return <svg width="14" height="14" viewBox="0 0 15 15" fill="none"><path d="M7.5 1C3.91015 1 1 3.91015 1 7.5C1 11.0899 3.91015 14 7.5 14C11.0899 14 14 11.0899 14 7.5C14 3.91015 11.0899 1 7.5 1ZM0 7.5C0 3.35786 3.35786 0 7.5 0C11.6421 0 15 3.35786 15 7.5C15 11.6421 11.6421 15 7.5 15C3.35786 15 0 11.6421 0 7.5ZM7.5 4C7.22386 4 7 4.22386 7 4.5C7 4.77614 7.22386 5 7.5 5C7.77614 5 8 4.77614 8 4.5C8 4.22386 7.77614 4 7.5 4ZM6.5 6.5C6.5 6.22386 6.72386 6 7 6H7.5C7.77614 6 8 6.22386 8 6.5V10H8.5C8.77614 10 9 10.2239 9 10.5C9 10.7761 8.77614 11 8.5 11H6.5C6.22386 11 6 10.7761 6 10.5C6 10.2239 6.22386 10 6.5 10H7V7H6.5C6.22386 7 6 6.77614 6 6.5Z" fill="currentColor" fillRule="evenodd" clipRule="evenodd" /></svg>
}
function IconPackage(): React.ReactElement {
  return <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/><path d="M3.27 6.96L12 12.01l8.73-5.05M12 22.08V12" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>
}

// ---------------------------------------------------------------------------
// Logo mark
// ---------------------------------------------------------------------------

function LogoMark({ size = 20 }: { size?: number }): React.ReactElement {
  return (
    <div className="rounded-xl bg-[#5e6ad2] flex items-center justify-center shrink-0" style={{ width: size, height: size }}>
      <svg width={size * 0.5} height={size * 0.5} viewBox="0 0 10 10" fill="none">
        <path d="M2.5 2L8 5L2.5 8V2Z" fill="white" />
      </svg>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Error boundary
// ---------------------------------------------------------------------------

interface EBState { hasError: boolean; error: string }
class ErrorBoundary extends Component<{ children: JSX.Element }, EBState> {
  state: EBState = { hasError: false, error: '' }
  static getDerivedStateFromError(err: Error): EBState {
    return { hasError: true, error: err.message }
  }
  componentDidCatch(err: Error): void { console.error('[Snagify]', err) }
  render(): JSX.Element {
    if (this.state.hasError) {
      return (
        <div className="flex h-screen items-center justify-center bg-[#0a0a0a] flex-col gap-6 px-8">
          <div className="w-14 h-14 rounded-2xl bg-[rgba(239,68,68,0.1)] border border-[rgba(239,68,68,0.2)] flex items-center justify-center text-[#ef4444]">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none"><path d="M12 9v4M12 17h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>
          </div>
          <div className="text-center space-y-2 max-w-sm">
            <p className="text-[16px] font-semibold text-[#eeeeee]">Something went wrong</p>
            <p className="text-[12px] text-[#5a5a5a] leading-relaxed">An unexpected error occurred. You can try to recover or restart the app.</p>
            {this.state.error && (
              <pre className="text-[10px] font-mono text-[#3a3a3a] mt-2 px-4 py-2.5 rounded-lg bg-[#0f0f0f] border border-[#1e1e1e] text-left whitespace-pre-wrap leading-relaxed max-h-28 overflow-y-auto">{this.state.error}</pre>
            )}
          </div>
          <button onClick={() => this.setState({ hasError: false, error: '' })} className="px-5 py-2.5 rounded-xl text-[13px] font-semibold text-white bg-[#5e6ad2] hover:bg-[#6b77df] transition-colors">
            Try to recover
          </button>
        </div>
      )
    }
    return this.props.children
  }
}

// ---------------------------------------------------------------------------
// Toast notification
// ---------------------------------------------------------------------------

interface ToastState { message: string; type: 'success' | 'error' }

function Toast({ toast, onDismiss }: { toast: ToastState; onDismiss: () => void }): React.ReactElement {
  useEffect(() => {
    const t = setTimeout(onDismiss, 3500)
    return () => clearTimeout(t)
  }, [onDismiss])
  return (
    <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 flex items-center gap-2.5 px-4 py-2.5 rounded-xl border shadow-2xl animate-in" style={{ backgroundColor: '#111111', borderColor: '#252525', boxShadow: '0 8px 32px rgba(0,0,0,0.6)' }}>
      <span className={toast.type === 'success' ? 'text-[#16a34a]' : 'text-[#ef4444]'}>
        {toast.type === 'success' ? <IconCheck /> : <IconX />}
      </span>
      <p className="text-[12px] font-medium text-[#eeeeee] whitespace-nowrap">{toast.message}</p>
    </div>
  )
}

// ---------------------------------------------------------------------------
// PDF generation
// ---------------------------------------------------------------------------

interface ReportBranding {
  company: string
  client: string
  logoDataUrl: string
  logoW: number
  logoH: number
}

function loadBranding(): ReportBranding {
  const empty: ReportBranding = { company: '', client: '', logoDataUrl: '', logoW: 0, logoH: 0 }
  try { return { ...empty, ...JSON.parse(localStorage.getItem('snagify-branding') ?? '{}') } } catch { return empty }
}

function saveBranding(b: ReportBranding): void {
  localStorage.setItem('snagify-branding', JSON.stringify(b))
}

function buildPdfReport(analysis: AnalysisResult, folderName: string, folderPath: string): Uint8Array {
  const doc = new jsPDF({ unit: 'mm', format: 'a4' })
  const PW = 210, PH = 297, ML = 20, MR = 20, CW = PW - ML - MR, BM = 20
  let y = 0

  const scoreRgb: [number, number, number] = analysis.securityScore >= 71 ? [22, 163, 74] : analysis.securityScore >= 41 ? [234, 179, 8] : [239, 68, 68]
  const scoreLabel = analysis.securityScore >= 71 ? 'Good' : analysis.securityScore >= 41 ? 'Fair' : 'At Risk'

  const SEV_CFG: Record<string, { label: string; rgb: [number, number, number] }> = {
    critical: { label: 'Critical', rgb: [239, 68, 68] },
    high:     { label: 'High',     rgb: [249, 115, 22] },
    medium:   { label: 'Medium',   rgb: [234, 179, 8] },
    low:      { label: 'Low',      rgb: [107, 114, 128] }
  }

  function ensureSpace(needed: number): void {
    if (y + needed > PH - BM) { doc.addPage(); y = 24 }
  }

  function sectionLabel(text: string): void {
    ensureSpace(14)
    doc.setFontSize(7)
    doc.setFont('helvetica', 'bold')
    doc.setTextColor(100, 100, 100)
    doc.text(text, ML, y)
    y += 5
    doc.setDrawColor(35, 35, 35)
    doc.setLineWidth(0.25)
    doc.line(ML, y, ML + CW, y)
    y += 6
  }

  // ── Header ────────────────────────────────────────────────────────────────
  const branding = loadBranding()
  const whiteLabel = Boolean(branding.company || branding.logoDataUrl)
  const titleX = whiteLabel ? ML : ML + 15

  doc.setFillColor(10, 10, 10)
  doc.rect(0, 0, PW, 50, 'F')
  // Purple left accent bar
  doc.setFillColor(94, 106, 210)
  doc.rect(0, 0, 4, 50, 'F')
  if (branding.logoDataUrl) {
    // Custom logo top-right, aspect-preserving within 30x14mm
    const maxH = 14, maxW = 30
    const ratio = branding.logoW > 0 && branding.logoH > 0 ? branding.logoW / branding.logoH : 1
    let lw = maxH * ratio, lh = maxH
    if (lw > maxW) { lw = maxW; lh = maxW / ratio }
    try { doc.addImage(branding.logoDataUrl, PW - MR - lw, 14, lw, lh) } catch { /* unsupported image format — skip logo */ }
  }
  if (!whiteLabel) {
    // Default Snagify logo square
    doc.setFillColor(94, 106, 210)
    doc.roundedRect(ML, 16, 11, 11, 2, 2, 'F')
    doc.setFontSize(7.5)
    doc.setFont('helvetica', 'bold')
    doc.setTextColor(255, 255, 255)
    doc.text('S', ML + 3.8, 24)
  }
  // Title
  doc.setFontSize(15)
  doc.setFont('helvetica', 'bold')
  doc.setTextColor(238, 238, 238)
  doc.text(whiteLabel ? 'Security Report' : 'Snagify Security Report', titleX, 23)
  // Meta
  const dateStr = new Date().toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })
  doc.setFontSize(8)
  doc.setFont('helvetica', 'normal')
  doc.setTextColor(110, 110, 110)
  doc.text(`${folderName}  \u00b7  ${dateStr}`, titleX, 31)
  doc.setFontSize(7)
  doc.setTextColor(70, 70, 70)
  const pathText = folderPath.length > 75 ? '\u2026' + folderPath.slice(-73) : folderPath
  doc.text(pathText, titleX, 39)
  if (branding.company || branding.client) {
    const parts: string[] = []
    if (branding.company) parts.push(`Prepared by ${branding.company}`)
    if (branding.client) parts.push(`for ${branding.client}`)
    doc.setFontSize(7.5)
    doc.setFont('helvetica', 'bold')
    doc.setTextColor(140, 140, 140)
    doc.text(parts.join(' '), titleX, 46)
  }

  y = 62

  // ── Score card ────────────────────────────────────────────────────────────
  // Card background
  doc.setFillColor(14, 14, 14)
  doc.roundedRect(ML, y - 6, CW, 32, 2, 2, 'F')
  // Colored left accent stripe
  doc.setFillColor(scoreRgb[0], scoreRgb[1], scoreRgb[2])
  doc.roundedRect(ML, y - 6, 4, 32, 1, 1, 'F')

  // Score label
  doc.setFontSize(6.5)
  doc.setFont('helvetica', 'bold')
  doc.setTextColor(90, 90, 90)
  doc.text('SECURITY SCORE', ML + 9, y - 1)

  // Big score number — positioned well below header (baseline at y+14, cap-top at ~y+3)
  doc.setFontSize(34)
  doc.setFont('helvetica', 'bold')
  doc.setTextColor(scoreRgb[0], scoreRgb[1], scoreRgb[2])
  doc.text(String(analysis.securityScore), ML + 9, y + 12)

  // / 100 label — aligned to right of number
  const numWidth = analysis.securityScore >= 100 ? 22 : analysis.securityScore >= 10 ? 16 : 10
  doc.setFontSize(11)
  doc.setFont('helvetica', 'normal')
  doc.setTextColor(scoreRgb[0], scoreRgb[1], scoreRgb[2])
  doc.text(`/ 100`, ML + 9 + numWidth + 2, y + 8)
  doc.setFontSize(9)
  doc.setTextColor(scoreRgb[0] * 0.7, scoreRgb[1] * 0.7, scoreRgb[2] * 0.7)
  doc.text(scoreLabel, ML + 9 + numWidth + 2, y + 14)

  // Severity counts — right side of card
  const sevCounts = [
    { label: 'Critical', count: analysis.criticalCount, rgb: [239, 68, 68] as [number, number, number] },
    { label: 'High',     count: analysis.highCount,     rgb: [249, 115, 22] as [number, number, number] },
    { label: 'Medium',   count: analysis.mediumCount,   rgb: [234, 179, 8] as [number, number, number] },
    { label: 'Low',      count: analysis.lowCount,      rgb: [107, 114, 128] as [number, number, number] }
  ]
  const colW = 36
  let cx = ML + CW - colW * 4 + colW / 2 + 2
  for (const s of sevCounts) {
    doc.setFontSize(17)
    doc.setFont('helvetica', 'bold')
    doc.setTextColor(s.count > 0 ? s.rgb[0] : 40, s.count > 0 ? s.rgb[1] : 40, s.count > 0 ? s.rgb[2] : 40)
    doc.text(String(s.count), cx, y + 8, { align: 'center' })
    doc.setFontSize(6)
    doc.setFont('helvetica', 'normal')
    doc.setTextColor(80, 80, 80)
    doc.text(s.label.toUpperCase(), cx, y + 15, { align: 'center' })
    cx += colW
  }

  y += 34

  // ── Executive summary ─────────────────────────────────────────────────────
  sectionLabel('EXECUTIVE SUMMARY')
  doc.setFontSize(9)
  doc.setFont('helvetica', 'normal')
  doc.setTextColor(75, 75, 75)
  const summaryLines = doc.splitTextToSize(analysis.summary, CW) as string[]
  ensureSpace(summaryLines.length * 5 + 6)
  doc.text(summaryLines, ML, y)
  y += summaryLines.length * 5 + 12

  // ── Findings table ────────────────────────────────────────────────────────
  sectionLabel('ALL FINDINGS')

  if (analysis.findings.length === 0) {
    doc.setFontSize(9)
    doc.setFont('helvetica', 'italic')
    doc.setTextColor(90, 90, 90)
    doc.text('No findings detected \u2014 codebase is clean.', ML, y)
    y += 10
  } else {
    // Table header row
    doc.setFillColor(18, 18, 18)
    doc.rect(ML, y - 4.5, CW, 8, 'F')
    doc.setFontSize(7)
    doc.setFont('helvetica', 'bold')
    doc.setTextColor(110, 110, 110)
    const C1 = ML + 2, C2 = ML + 26, C3 = ML + 114, C4 = ML + 154
    doc.text('SEV', C1, y)
    doc.text('TITLE', C2, y)
    doc.text('FILE', C3, y)
    doc.text('LINE', C4, y)
    y += 5

    let rowAlt = false
    for (const f of analysis.findings) {
      ensureSpace(9)
      if (rowAlt) {
        doc.setFillColor(15, 15, 15)
        doc.rect(ML, y - 4.5, CW, 8, 'F')
      }
      rowAlt = !rowAlt

      const sev = SEV_CFG[f.severity] ?? { label: f.severity, rgb: [107, 114, 128] as [number, number, number] }
      doc.setFontSize(7)
      doc.setFont('helvetica', 'bold')
      doc.setTextColor(sev.rgb[0], sev.rgb[1], sev.rgb[2])
      doc.text(sev.label, C1, y)

      doc.setFont('helvetica', 'normal')
      doc.setTextColor(65, 65, 65)
      const titleT = f.title.length > 44 ? f.title.slice(0, 42) + '\u2026' : f.title
      doc.text(titleT, C2, y)

      const fname = (f.file ?? '').split('/').pop() ?? ''
      doc.text(fname.length > 22 ? '\u2026' + fname.slice(-20) : fname, C3, y)
      doc.text(f.line !== null ? String(f.line) : '\u2014', C4, y)

      doc.setDrawColor(25, 25, 25)
      doc.setLineWidth(0.15)
      doc.line(ML, y + 3, ML + CW, y + 3)
      y += 8.5
    }
  }

  y += 8

  // ── Critical & High detail ────────────────────────────────────────────────
  const detailFindings = analysis.findings.filter(f => f.severity === 'critical' || f.severity === 'high')
  if (detailFindings.length > 0) {
    sectionLabel('CRITICAL & HIGH FINDINGS \u2014 DETAIL')

    for (const f of detailFindings) {
      ensureSpace(40)
      const sRgb = SEV_CFG[f.severity]?.rgb ?? [249, 115, 22] as [number, number, number]

      // Severity pill + title
      doc.setFontSize(7)
      doc.setFont('helvetica', 'bold')
      doc.setTextColor(sRgb[0], sRgb[1], sRgb[2])
      doc.text(f.severity.toUpperCase(), ML, y)

      doc.setFontSize(10.5)
      doc.setFont('helvetica', 'bold')
      doc.setTextColor(50, 50, 50)
      const titleLines = doc.splitTextToSize(f.title, CW - 22) as string[]
      doc.text(titleLines, ML + 20, y)
      y += titleLines.length * 5.5 + 2

      // File ref
      if (f.file) {
        doc.setFontSize(7.5)
        doc.setFont('helvetica', 'normal')
        doc.setTextColor(100, 100, 100)
        doc.text(f.line !== null ? `${f.file}:${f.line}` : f.file, ML, y)
        y += 5
      }

      // Standards mapping (CWE / OWASP)
      const standards = [...(f.cwe ?? []), ...(f.owasp ?? [])]
      if (standards.length > 0) {
        doc.setFontSize(7)
        doc.setFont('helvetica', 'bold')
        doc.setTextColor(94, 106, 210)
        doc.text(standards.join('  ·  '), ML, y)
        y += 5
      }

      // Explanation
      doc.setFontSize(8.5)
      doc.setFont('helvetica', 'normal')
      doc.setTextColor(75, 75, 75)
      const explLines = doc.splitTextToSize(f.explanation, CW) as string[]
      ensureSpace(explLines.length * 4.8 + 10)
      doc.text(explLines, ML, y)
      y += explLines.length * 4.8 + 6

      // Fix suggestion
      doc.setFontSize(6.5)
      doc.setFont('helvetica', 'bold')
      doc.setTextColor(94, 106, 210)
      doc.text('FIX SUGGESTION', ML, y)
      y += 4.5

      doc.setFontSize(8.5)
      doc.setFont('helvetica', 'normal')
      doc.setTextColor(75, 75, 75)
      const fixLines = doc.splitTextToSize(f.fixSuggestion, CW) as string[]
      ensureSpace(fixLines.length * 4.8 + 12)
      doc.text(fixLines, ML, y)
      y += fixLines.length * 4.8 + 10

      doc.setDrawColor(30, 30, 30)
      doc.setLineWidth(0.25)
      doc.line(ML, y, ML + CW, y)
      y += 9
    }
  }

  // ── Compliance issues ─────────────────────────────────────────────────────
  if (analysis.complianceIssues && analysis.complianceIssues.length > 0) {
    sectionLabel('COMPLIANCE VIOLATIONS')

    for (const issue of analysis.complianceIssues) {
      ensureSpace(30)
      // Regulation badge
      doc.setFontSize(7)
      doc.setFont('helvetica', 'bold')
      doc.setTextColor(234, 179, 8)
      doc.text(issue.regulation, ML, y)
      if (issue.article) {
        doc.setFontSize(7)
        doc.setFont('helvetica', 'normal')
        doc.setTextColor(120, 100, 30)
        doc.text(issue.article, ML + doc.getTextWidth(issue.regulation) + 3, y)
      }
      y += 5

      doc.setFontSize(8.5)
      doc.setFont('helvetica', 'normal')
      doc.setTextColor(75, 75, 75)
      const descLines = doc.splitTextToSize(issue.description, CW) as string[]
      ensureSpace(descLines.length * 4.8 + 8)
      doc.text(descLines, ML, y)
      y += descLines.length * 4.8 + 4

      doc.setFontSize(7)
      doc.setFont('helvetica', 'bold')
      doc.setTextColor(94, 106, 210)
      doc.text('RECOMMENDATION', ML, y)
      y += 4.5

      doc.setFontSize(8.5)
      doc.setFont('helvetica', 'normal')
      doc.setTextColor(75, 75, 75)
      const recLines = doc.splitTextToSize(issue.recommendation, CW) as string[]
      ensureSpace(recLines.length * 4.8 + 10)
      doc.text(recLines, ML, y)
      y += recLines.length * 4.8 + 10

      doc.setDrawColor(40, 35, 10)
      doc.setLineWidth(0.2)
      doc.line(ML, y, ML + CW, y)
      y += 8
    }
  }

  // ── Scalability analysis ──────────────────────────────────────────────────
  if (analysis.scalability) {
    const scale = analysis.scalability
    sectionLabel('SCALABILITY ANALYSIS')

    const scaleRgb: [number, number, number] = scale.scalabilityScore >= 71 ? [22, 163, 74] : scale.scalabilityScore >= 41 ? [234, 179, 8] : [239, 68, 68]
    doc.setFontSize(11)
    doc.setFont('helvetica', 'bold')
    doc.setTextColor(scaleRgb[0], scaleRgb[1], scaleRgb[2])
    doc.text(`Load readiness: ${scale.scalabilityScore}/100`, ML, y)
    y += 6

    doc.setFontSize(8.5)
    doc.setFont('helvetica', 'normal')
    doc.setTextColor(75, 75, 75)
    const scaleSummary = doc.splitTextToSize(scale.summary, CW) as string[]
    ensureSpace(scaleSummary.length * 4.8 + 8)
    doc.text(scaleSummary, ML, y)
    y += scaleSummary.length * 4.8 + 8

    for (const b of scale.bottlenecks) {
      ensureSpace(28)
      const riskRgb = SEV_CFG[b.risk]?.rgb ?? SEV_CFG.medium.rgb
      doc.setFontSize(7)
      doc.setFont('helvetica', 'bold')
      doc.setTextColor(riskRgb[0], riskRgb[1], riskRgb[2])
      doc.text(b.risk.toUpperCase(), ML, y)
      doc.setTextColor(110, 110, 110)
      doc.text(b.area.toUpperCase(), ML + 20, y)
      y += 5

      doc.setFontSize(10)
      doc.setFont('helvetica', 'bold')
      doc.setTextColor(50, 50, 50)
      const bTitle = doc.splitTextToSize(b.title, CW) as string[]
      doc.text(bTitle, ML, y)
      y += bTitle.length * 5.2 + 2

      if (b.impact) {
        doc.setFontSize(8.5)
        doc.setFont('helvetica', 'normal')
        doc.setTextColor(75, 75, 75)
        const impLines = doc.splitTextToSize(`Under load: ${b.impact}`, CW) as string[]
        ensureSpace(impLines.length * 4.8 + 8)
        doc.text(impLines, ML, y)
        y += impLines.length * 4.8 + 3
      }
      if (b.recommendation) {
        doc.setFontSize(6.5)
        doc.setFont('helvetica', 'bold')
        doc.setTextColor(94, 106, 210)
        doc.text('FIX', ML, y)
        y += 4
        doc.setFontSize(8.5)
        doc.setFont('helvetica', 'normal')
        doc.setTextColor(75, 75, 75)
        const fixLines = doc.splitTextToSize(b.recommendation, CW) as string[]
        ensureSpace(fixLines.length * 4.8 + 10)
        doc.text(fixLines, ML, y)
        y += fixLines.length * 4.8 + 6
      }

      doc.setDrawColor(30, 30, 30)
      doc.setLineWidth(0.25)
      doc.line(ML, y, ML + CW, y)
      y += 8
    }
  }

  // ── Footer on every page ──────────────────────────────────────────────────
  const totalPages = doc.getNumberOfPages()
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i)
    doc.setFillColor(14, 14, 14)
    doc.rect(0, PH - BM, PW, BM, 'F')
    doc.setFontSize(7)
    doc.setFont('helvetica', 'normal')
    doc.setTextColor(70, 70, 70)
    doc.text('Generated by Snagify \u2014 snagify.ca', ML, PH - 8)
    doc.setTextColor(90, 90, 90)
    doc.text(`${i} / ${totalPages}`, PW - MR, PH - 8, { align: 'right' })
  }

  return new Uint8Array(doc.output('arraybuffer') as ArrayBuffer)
}

function buildShareableSummary(analysis: AnalysisResult, folderName: string): string {
  const date = new Date().toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })
  return [
    `Snagify Security Report — ${folderName}`,
    `Score: ${analysis.securityScore}/100`,
    `Critical: ${analysis.criticalCount} | High: ${analysis.highCount} | Medium: ${analysis.mediumCount} | Low: ${analysis.lowCount}`,
    `Generated ${date} — snagify.ca`
  ].join('\n')
}


// ---------------------------------------------------------------------------
// Account login screen (Supabase) — used when account auth is configured
// ---------------------------------------------------------------------------

function AccountLoginScreen({ onLicensed }: { onLicensed: (info: AuthSessionInfo) => void }): React.ReactElement {
  const [mode, setMode] = useState<'signin' | 'signup'>('signin')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [session, setSession] = useState<AuthSessionInfo | null>(null)
  const [refreshing, setRefreshing] = useState(false)

  const inputCls = 'w-full px-3 py-2.5 rounded-lg text-[13px] bg-[#0a0a0a] border border-[#222222] text-[#eeeeee] placeholder-[#333333] focus:outline-none focus:border-[#5e6ad2] transition-colors'
  const inputStyle = { WebkitUserSelect: 'text', userSelect: 'text' } as React.CSSProperties

  const handleSubmit = useCallback(async (): Promise<void> => {
    if (loading || !email.trim() || !password) return
    setLoading(true); setError(null); setNotice(null)
    try {
      const info = mode === 'signin'
        ? await window.api.authSignIn(email.trim(), password)
        : await window.api.authSignUp(email.trim(), password)
      if (!info.signedIn) {
        setNotice('Account created — check your email to confirm, then sign in.')
        setMode('signin')
      } else if (info.licensed) {
        onLicensed(info)
      } else {
        setSession(info)
      }
    } catch (err) {
      setError(String(err).replace(/Error invoking remote method '[^']+': /, '').replace(/^Error: /, ''))
    } finally { setLoading(false) }
  }, [loading, email, password, mode, onLicensed])

  const handleRefreshLicense = useCallback(async (): Promise<void> => {
    setRefreshing(true)
    try {
      const info = await window.api.authGetSession()
      if (info.signedIn && info.licensed) { onLicensed(info); return }
      setSession(info.signedIn ? info : null)
    } finally { setRefreshing(false) }
  }, [onLicensed])

  const handleSignOut = useCallback(async (): Promise<void> => {
    await window.api.authSignOut()
    setSession(null); setEmail(''); setPassword('')
  }, [])

  // Signed in but no active license — purchase prompt
  if (session) {
    return (
      <div className="flex h-screen items-center justify-center bg-[#0a0a0a] px-6">
        <div className="w-full max-w-sm space-y-5">
          <div className="flex justify-center"><LogoMark size={40} /></div>
          <div className="text-center space-y-1">
            <p className="text-[15px] font-semibold text-[#eeeeee]">Signed in as {session.email}</p>
            <p className="text-[12px] text-[#5a5a5a]">No active license on this account yet. Purchase one on the website and it activates here automatically.</p>
          </div>
          <button onClick={() => window.open('https://snagify.ca', '_blank')} className="w-full py-3 rounded-xl text-[13px] font-semibold text-white bg-[#5e6ad2] hover:bg-[#6b77df] transition-colors">Purchase on snagify.ca</button>
          <button onClick={handleRefreshLicense} disabled={refreshing} className="w-full py-2.5 rounded-xl text-[13px] font-semibold text-[#eeeeee] bg-[#1a1a1a] hover:bg-[#222222] border border-[#252525] disabled:opacity-40 transition-all">{refreshing ? 'Checking…' : 'I purchased — check again'}</button>
          <button onClick={handleSignOut} className="w-full text-[12px] font-medium text-[#5a5a5a] hover:text-[#eeeeee] transition-colors">Sign out</button>
        </div>
      </div>
    )
  }

  return (
    <div className="flex h-screen items-center justify-center bg-[#0a0a0a] px-6">
      <div className="w-full max-w-sm space-y-5">
        <div className="flex justify-center"><LogoMark size={40} /></div>
        <div className="text-center space-y-1">
          <p className="text-[15px] font-semibold text-[#eeeeee]">{mode === 'signin' ? 'Sign in to Snagify' : 'Create your Snagify account'}</p>
          <p className="text-[12px] text-[#5a5a5a]">{mode === 'signin' ? 'Your license activates automatically after sign-in' : 'Then purchase a license on snagify.ca'}</p>
        </div>
        <div className="space-y-2.5">
          <input type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="Email" className={inputCls} style={inputStyle} autoComplete="off" spellCheck={false} />
          <input type="password" value={password} onChange={e => setPassword(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleSubmit()} placeholder={mode === 'signup' ? 'Password (min 8 characters)' : 'Password'} className={inputCls} style={inputStyle} />
          {error && <p className="text-[12px] text-[#f87171]">{error}</p>}
          {notice && <p className="text-[12px] text-[#16a34a]">{notice}</p>}
          <button onClick={handleSubmit} disabled={loading || !email.trim() || !password} className="w-full py-3 rounded-xl text-[13px] font-semibold text-white bg-[#5e6ad2] hover:bg-[#6b77df] disabled:opacity-40 disabled:cursor-not-allowed transition-colors flex items-center justify-center gap-2">
            {loading ? <><div className="w-3.5 h-3.5 rounded-full border border-white/30 border-t-white animate-spin" />{mode === 'signin' ? 'Signing in…' : 'Creating account…'}</> : mode === 'signin' ? 'Sign in' : 'Create account'}
          </button>
        </div>
        <div className="text-center">
          <button onClick={() => { setMode(m => m === 'signin' ? 'signup' : 'signin'); setError(null); setNotice(null) }} className="text-[12px] font-medium text-[#5e6ad2] hover:text-[#7b87e5] transition-colors">
            {mode === 'signin' ? "Don't have an account? Create one" : 'Already have an account? Sign in'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// License activation screen
// ---------------------------------------------------------------------------

function LicenseActivationScreen({ onActivated }: { onActivated: (email: string) => void }): React.ReactElement {
  const [key, setKey] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleActivate = useCallback(async (): Promise<void> => {
    const trimmed = key.trim()
    if (!trimmed) return
    setLoading(true); setError(null)
    try {
      const result = await window.api.validateLicense(trimmed)
      if (result.valid) { onActivated(result.customerEmail) }
      else { setError(result.error ?? 'License key is not valid.') }
    } catch (err) { setError(String(err)) }
    finally { setLoading(false) }
  }, [key, onActivated])

  return (
    <div className="flex h-screen flex-col items-center justify-center bg-[#0a0a0a] select-none">
      <div className="absolute inset-0 opacity-[0.03]" style={{ backgroundImage: 'linear-gradient(#fff 1px, transparent 1px), linear-gradient(90deg, #fff 1px, transparent 1px)', backgroundSize: '40px 40px' }} />
      <div className="relative z-10 w-full max-w-[380px] px-6 space-y-8">
        <div className="flex flex-col items-center gap-3">
          <LogoMark size={48} />
          <div className="text-center">
            <h1 className="text-[22px] font-bold tracking-tight text-[#eeeeee]">Snagify</h1>
            <p className="text-[13px] text-[#3a3a3a] mt-1">Security analysis for your codebase</p>
          </div>
        </div>
        <div className="rounded-2xl border border-[#1e1e1e] bg-[#0d0d0d] overflow-hidden">
          <div className="px-6 py-5 border-b border-[#181818]">
            <p className="text-[13px] font-semibold text-[#eeeeee]">Activate your license</p>
            <p className="text-[12px] text-[#3a3a3a] mt-0.5">Enter the license key from your purchase email</p>
          </div>
          <div className="px-6 py-5 space-y-3">
            <input type="text" value={key} onChange={(e) => { setKey(e.target.value); setError(null) }} onKeyDown={(e) => e.key === 'Enter' && handleActivate()} placeholder="XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" className="w-full px-3.5 py-2.5 rounded-xl text-[13px] font-mono bg-[#0a0a0a] border border-[#222222] text-[#eeeeee] placeholder-[#2a2a2a] focus:outline-none focus:border-[#5e6ad2] transition-colors select-text" style={{ WebkitUserSelect: 'text', userSelect: 'text' } as React.CSSProperties} spellCheck={false} autoComplete="off" />
            {error && <div className="flex items-start gap-2 px-3 py-2.5 rounded-lg bg-[#150a0a] border border-[#2a1010]"><span className="text-[#ef4444] shrink-0 mt-0.5"><IconX /></span><p className="text-[12px] text-[#f87171] leading-snug">{error}</p></div>}
            <button onClick={handleActivate} disabled={loading || !key.trim()} className="w-full py-3 rounded-xl text-[13px] font-semibold text-white bg-[#5e6ad2] hover:bg-[#6b77df] disabled:opacity-40 disabled:cursor-not-allowed transition-colors flex items-center justify-center gap-2">
              {loading ? <><div className="w-3.5 h-3.5 rounded-full border border-white/30 border-t-white animate-spin" />Activating…</> : 'Activate License'}
            </button>
          </div>
        </div>
        <div className="text-center space-y-1">
          <p className="text-[12px] text-[#2a2a2a]">Don't have a license?</p>
          <button onClick={() => window.open('https://snagify.ca', '_blank')} className="text-[12px] font-medium text-[#5e6ad2] hover:text-[#7b87e5] transition-colors">Get one at snagify.ca</button>
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Shared: score circle
// ---------------------------------------------------------------------------

function ScoreCircle({ score, size = 'md' }: { score: number; size?: 'sm' | 'md' }): React.ReactElement {
  const color = getScoreColor(score)
  const glowRgba = score >= 71 ? 'rgba(22,163,74,0.25)' : score >= 41 ? 'rgba(234,179,8,0.25)' : 'rgba(239,68,68,0.25)'
  const isSm = size === 'sm'
  const dim = isSm ? 64 : 96
  const r = isSm ? 25 : 38
  const circ = 2 * Math.PI * r
  const cx = dim / 2, cy = dim / 2
  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative flex items-center justify-center" style={{ width: dim, height: dim }}>
        <svg width={dim} height={dim} viewBox={`0 0 ${dim} ${dim}`} className="absolute inset-0 -rotate-90" style={{ filter: `drop-shadow(0 0 ${isSm ? 6 : 10}px ${glowRgba})` }}>
          <circle cx={cx} cy={cy} r={r} stroke="#1e1e1e" strokeWidth={isSm ? 4 : 6} fill="none" />
          <circle cx={cx} cy={cy} r={r} stroke={color} strokeWidth={isSm ? 4 : 6} fill="none" strokeLinecap="round"
            strokeDasharray={circ} strokeDashoffset={circ - (score / 100) * circ}
            style={{ transition: 'stroke-dashoffset 0.7s cubic-bezier(0.34,1.56,0.64,1)' }} />
        </svg>
        <div className="relative text-center">
          <span className={`font-bold leading-none tabular-nums ${isSm ? 'text-[18px]' : 'text-[26px]'}`} style={{ color }}>{score}</span>
          {!isSm && <span className="block text-[9px] font-semibold text-[#3a3a3a] uppercase tracking-widest mt-0.5">score</span>}
        </div>
      </div>
      <span className={`font-semibold ${isSm ? 'text-[10px]' : 'text-[11px]'}`} style={{ color }}>{score >= 71 ? 'Good' : score >= 41 ? 'Fair' : 'Critical'}</span>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Shared: AI finding card + severity section + analysis panel
// ---------------------------------------------------------------------------

type PatchState =
  | { phase: 'idle' }
  | { phase: 'generating' }
  | { phase: 'preview'; patch: FixPatch }
  | { phase: 'applying'; patch: FixPatch }
  | { phase: 'applied'; patch: FixPatch; backupId: string }
  | { phase: 'error'; message: string }

function SectionLabel({ text }: { text: string }): React.ReactElement {
  return (
    <div className="flex items-center gap-2.5 px-1 pt-1">
      <span className="text-[10px] font-bold uppercase tracking-widest text-[#4a4a4a] shrink-0">{text}</span>
      <div className="h-px flex-1 bg-[#1a1a1a]" />
    </div>
  )
}

function AIFindingCard({ finding, folderPath }: { finding: AIFinding; folderPath?: string | null }): React.ReactElement {
  const cfg = SEVERITY_CONFIG[finding.severity] ?? SEVERITY_CONFIG.low
  const fileName = finding.file ? finding.file.split('/').pop() ?? finding.file : ''
  const [expanded, setExpanded] = useState(finding.severity === 'critical' || finding.severity === 'high')
  const [patch, setPatch] = useState<PatchState>({ phase: 'idle' })
  const [ignored, setIgnored] = useState(false)
  const canPatch = Boolean(folderPath && finding.file)

  const handleIgnore = useCallback(async (): Promise<void> => {
    if (!folderPath) return
    try {
      await window.api.suppressFinding(folderPath, finding)
      setIgnored(true)
    } catch { /* leave card as-is */ }
  }, [folderPath, finding])

  const handleRestore = useCallback(async (): Promise<void> => {
    if (!folderPath) return
    const key = `${finding.file}|${finding.title.toLowerCase().trim()}`
    try {
      await window.api.unsuppressFinding(folderPath, key)
      setIgnored(false)
    } catch { /* leave card as-is */ }
  }, [folderPath, finding])

  const handleGenerate = useCallback(async (): Promise<void> => {
    if (!folderPath) return
    setPatch({ phase: 'generating' })
    try {
      const p = await window.api.generateFix(folderPath, finding)
      setPatch({ phase: 'preview', patch: p })
    } catch (err) {
      setPatch({ phase: 'error', message: String(err).replace(/^Error: /, '').replace(/Error invoking remote method '[^']+': /, '') })
    }
  }, [folderPath, finding])

  const handleApply = useCallback(async (p: FixPatch): Promise<void> => {
    if (!folderPath) return
    setPatch({ phase: 'applying', patch: p })
    try {
      const { backupId } = await window.api.applyFix(folderPath, p)
      setPatch({ phase: 'applied', patch: p, backupId })
    } catch (err) {
      setPatch({ phase: 'error', message: String(err).replace(/^Error: /, '').replace(/Error invoking remote method '[^']+': /, '') })
    }
  }, [folderPath])

  const handleUndo = useCallback(async (backupId: string): Promise<void> => {
    try {
      await window.api.revertFix(backupId)
      setPatch({ phase: 'idle' })
    } catch (err) {
      setPatch({ phase: 'error', message: String(err).replace(/^Error: /, '').replace(/Error invoking remote method '[^']+': /, '') })
    }
  }, [])

  if (ignored) {
    return (
      <div className="rounded-xl border border-[#1e1e1e] bg-[#0d0d0d] px-3.5 py-3 flex items-center gap-3">
        <span className="shrink-0 px-1.5 py-[2px] rounded text-[9px] font-bold uppercase tracking-wider text-[#3a3a3a] border border-[#222222]">Ignored</span>
        <p className="text-[12px] text-[#4a4a4a] line-through truncate flex-1">{finding.title}</p>
        <button onClick={handleRestore} className="shrink-0 px-2.5 py-1 rounded-md text-[11px] font-medium text-[#5a5a5a] hover:text-[#eeeeee] border border-[#222222] hover:border-[#333333] transition-all">Restore</button>
      </div>
    )
  }

  return (
    <div className="rounded-xl border overflow-hidden" style={{ borderColor: cfg.border }}>
      {/* Header row — always visible */}
      <button
        onClick={() => setExpanded(v => !v)}
        className="w-full flex items-start gap-3 p-3.5 text-left transition-colors"
        style={{ backgroundColor: cfg.bg }}
      >
        <span className="shrink-0 mt-[1px] px-1.5 py-[2px] rounded text-[9px] font-bold uppercase tracking-wider" style={{ color: cfg.color, border: `1px solid ${cfg.border}` }}>{cfg.label}</span>
        <div className="flex-1 min-w-0">
          <p className="text-[12px] font-semibold text-[#eeeeee] leading-snug">{finding.title}</p>
          {finding.file && (
            <div className="flex items-center gap-1 mt-1 text-[10px] font-mono" style={{ color: cfg.color, opacity: 0.6 }}>
              <span><IconFile /></span>
              <span className="truncate max-w-[200px]">{fileName}</span>
              {finding.line !== null && <span>:{finding.line}</span>}
            </div>
          )}
        </div>
        <span className={`shrink-0 mt-0.5 text-[#3a3a3a] transition-transform duration-150 ${expanded ? 'rotate-180' : ''}`}><IconChevronDown /></span>
      </button>
      {/* Expandable detail */}
      {expanded && (
        <div className="px-3.5 pb-3.5 pt-2.5 space-y-2.5 bg-[#080808]">
          <p className="text-[12px] text-[#8a8a8a] leading-relaxed">{finding.explanation}</p>
          {((finding.cwe?.length ?? 0) > 0 || (finding.owasp?.length ?? 0) > 0) && (
            <div className="flex items-center gap-1.5 flex-wrap">
              {(finding.cwe ?? []).map(c => (
                <span key={c} className="px-2 py-[3px] rounded-md text-[10px] font-mono font-medium text-[#8a8a8a] bg-[#141414] border border-[#222222]">{c}</span>
              ))}
              {(finding.owasp ?? []).map(o => (
                <span key={o} className="px-2 py-[3px] rounded-md text-[10px] font-mono font-medium text-[#7b86e0] bg-[#5e6ad2]/10 border border-[#5e6ad2]/25">{o}</span>
              ))}
            </div>
          )}
          <div className="rounded-lg border border-[#5e6ad2]/20 bg-[#5e6ad2]/5 px-3 py-2.5 space-y-1">
            <p className="text-[9px] uppercase tracking-widest font-semibold text-[#5e6ad2]/60">Fix suggestion</p>
            <p className="text-[12px] text-[#b4b4b4] leading-relaxed">{finding.fixSuggestion}</p>
          </div>

          {/* AI patch workflow */}
          {patch.phase === 'idle' && folderPath && (
            <div className="flex gap-1.5">
              {canPatch && (
                <button onClick={handleGenerate} className="flex-1 py-2 rounded-lg text-[12px] font-semibold text-[#5e6ad2] bg-[#5e6ad2]/10 hover:bg-[#5e6ad2]/15 border border-[#5e6ad2]/25 hover:border-[#5e6ad2]/40 transition-all flex items-center justify-center gap-1.5">
                  ✨ Generate patch
                </button>
              )}
              <button onClick={handleIgnore} title="Mark as false positive — excluded from future scans of this project" className={`py-2 rounded-lg text-[12px] font-medium text-[#4a4a4a] hover:text-[#8a8a8a] border border-[#1e1e1e] hover:border-[#2e2e2e] transition-all ${canPatch ? 'px-3.5' : 'flex-1'}`}>
                Ignore
              </button>
            </div>
          )}
          {patch.phase === 'generating' && (
            <div className="w-full py-2 rounded-lg text-[12px] font-medium text-[#5a5a5a] bg-[#101010] border border-[#1e1e1e] flex items-center justify-center gap-2">
              <div className="w-3 h-3 rounded-full border border-[#3a3a3a] border-t-[#5e6ad2] animate-spin" />
              Generating patch with AI…
            </div>
          )}
          {(patch.phase === 'preview' || patch.phase === 'applying') && (
            <div className="rounded-lg border border-[#1e1e1e] bg-[#0a0a0a] overflow-hidden">
              <div className="px-3 py-2 border-b border-[#181818] flex items-center gap-2">
                <p className="text-[10px] uppercase tracking-widest font-semibold text-[#5a5a5a] flex-1">Proposed patch</p>
                <span className="text-[10px] font-mono text-[#3a3a3a] truncate max-w-[180px]">{patch.patch.file}</span>
              </div>
              {patch.patch.explanation && <p className="px-3 pt-2 text-[11px] text-[#7a7a7a] leading-relaxed">{patch.patch.explanation}</p>}
              <div className="p-2 space-y-1.5">
                <pre className="text-[10.5px] font-mono leading-relaxed text-[#f0a0a0] bg-[#180a0a] border border-[#2a1212] rounded-md px-2.5 py-2 overflow-x-auto whitespace-pre max-h-[140px] overflow-y-auto">{patch.patch.search.split('\n').map(l => `- ${l}`).join('\n')}</pre>
                <pre className="text-[10.5px] font-mono leading-relaxed text-[#9fd6a5] bg-[#0a180c] border border-[#12301a] rounded-md px-2.5 py-2 overflow-x-auto whitespace-pre max-h-[140px] overflow-y-auto">{patch.patch.replace.split('\n').map(l => `+ ${l}`).join('\n')}</pre>
              </div>
              <div className="px-2 pb-2 flex gap-1.5">
                <button
                  onClick={() => handleApply(patch.patch)}
                  disabled={patch.phase === 'applying'}
                  className="flex-1 py-2 rounded-lg text-[12px] font-semibold text-white bg-[#16a34a] hover:bg-[#15803d] disabled:opacity-50 transition-colors flex items-center justify-center gap-1.5"
                >
                  {patch.phase === 'applying' ? <><div className="w-3 h-3 rounded-full border border-white/30 border-t-white animate-spin" />Applying…</> : <><IconCheck />Apply patch</>}
                </button>
                <button onClick={() => setPatch({ phase: 'idle' })} disabled={patch.phase === 'applying'} className="px-4 py-2 rounded-lg text-[12px] font-medium text-[#5a5a5a] hover:text-[#eeeeee] border border-[#222222] hover:border-[#333333] transition-all">Discard</button>
              </div>
            </div>
          )}
          {patch.phase === 'applied' && (
            <div className="rounded-lg border border-[#166534]/30 bg-[#166534]/10 px-3 py-2.5 flex items-center gap-2.5">
              <span className="text-[#16a34a] shrink-0"><IconCheck /></span>
              <p className="text-[12px] text-[#16a34a] font-medium flex-1">Patch applied to {patch.patch.file}</p>
              <button onClick={() => handleUndo(patch.backupId)} className="shrink-0 px-2.5 py-1 rounded-md text-[11px] font-medium text-[#5a5a5a] hover:text-[#eeeeee] border border-[#222222] hover:border-[#333333] transition-all">Undo</button>
            </div>
          )}
          {patch.phase === 'error' && (
            <div className="rounded-lg border border-[#2a1515] bg-[#150a0a] px-3 py-2.5 space-y-1.5">
              <p className="text-[11px] text-[#f87171] leading-relaxed">{patch.message}</p>
              <button onClick={handleGenerate} className="text-[11px] font-medium text-[#5e6ad2] hover:text-[#7b86e0] transition-colors">Try again</button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function SeveritySection({ severity, findings, folderPath }: { severity: Severity; findings: AIFinding[]; folderPath?: string | null }): React.ReactElement | null {
  const [open, setOpen] = useState(severity === 'critical' || severity === 'high')
  const cfg = SEVERITY_CONFIG[severity]
  if (!findings.length) return null
  return (
    <div className="rounded-xl border border-[#1e1e1e] overflow-hidden">
      <button onClick={() => setOpen(v => !v)} className="w-full flex items-center gap-3 px-4 py-3 bg-[#0f0f0f] hover:bg-[#111111] transition-colors">
        <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: cfg.color }} />
        <span className="text-[13px] font-semibold text-[#eeeeee] flex-1 text-left">{cfg.label}</span>
        <span className="text-[11px] font-mono tabular-nums" style={{ color: cfg.color }}>{findings.length}</span>
        <span className={`text-[#3a3a3a] transition-transform duration-150 ${open ? 'rotate-180' : ''}`}><IconChevronDown /></span>
      </button>
      {open && <div className="px-4 pb-4 pt-2 space-y-3 bg-[#0a0a0a]">{findings.map(f => <AIFindingCard key={f.id} finding={f} folderPath={folderPath} />)}</div>}
    </div>
  )
}

function AIAnalysisPanel({ analysis, folderPath }: { analysis: AnalysisResult; folderPath?: string | null }): React.ReactElement {
  const bySev: Record<Severity, AIFinding[]> = { critical: [], high: [], medium: [], low: [] }
  for (const f of analysis.findings) { if (f.severity in bySev) bySev[f.severity].push(f) }
  const scoreColor = getScoreColor(analysis.securityScore)
  const scoreStatus = analysis.securityScore >= 71 ? 'Good' : analysis.securityScore >= 41 ? 'Fair' : 'At risk'
  return (
    <div className="space-y-3">
      {/* Executive summary box */}
      <div className="rounded-xl border border-[#1e1e1e] bg-[#0f0f0f] overflow-hidden">
        <div className="px-4 py-3 border-b border-[#181818] flex items-center gap-2">
          <span className="text-[#5e6ad2]"><IconShield /></span>
          <p className="text-[11px] font-semibold text-[#eeeeee] uppercase tracking-widest">Executive Summary</p>
          <span className="ml-auto text-[11px] font-bold px-2 py-0.5 rounded-full" style={{ color: scoreColor, backgroundColor: scoreColor + '18' }}>{scoreStatus}</span>
        </div>
        <div className="p-4 relative overflow-hidden">
          <div className="absolute -top-6 -right-6 w-28 h-28 rounded-full pointer-events-none" style={{ background: `radial-gradient(circle, ${scoreColor}12 0%, transparent 70%)` }} />
          <div className="flex items-start gap-5">
            <div className="shrink-0"><ScoreCircle score={analysis.securityScore} /></div>
            <p className="flex-1 min-w-0 text-[12px] text-[#8a8a8a] leading-relaxed pt-1">{analysis.summary}</p>
          </div>
        </div>
        {/* Severity breakdown */}
        <div className="grid grid-cols-4 gap-2 px-4 pb-4">
          {(['critical', 'high', 'medium', 'low'] as Severity[]).map(sev => {
            const cfg = SEVERITY_CONFIG[sev]
            const count = analysis[`${sev}Count` as keyof AnalysisResult] as number
            return (
              <div key={sev} className="flex flex-col gap-1.5 px-3 py-3 rounded-xl text-center" style={{ background: count > 0 ? cfg.bg : '#0a0a0a', border: `1px solid ${count > 0 ? cfg.border : '#1e1e1e'}` }}>
                <span className="text-[9px] font-bold uppercase tracking-wider" style={{ color: count > 0 ? cfg.color : '#3a3a3a' }}>{cfg.label}</span>
                <span className="text-[22px] font-bold tabular-nums leading-none" style={{ color: count > 0 ? cfg.color : '#2a2a2a' }}>{count}</span>
              </div>
            )
          })}
        </div>
      </div>

      {/* Findings box */}
      {analysis.findings.length > 0 ? (
        <div className="rounded-xl border border-[#1e1e1e] bg-[#0f0f0f] overflow-hidden">
          <div className="px-4 py-3 border-b border-[#181818] flex items-center gap-2">
            <span className="text-[#5e6ad2]"><IconFile /></span>
            <p className="text-[11px] font-semibold text-[#eeeeee] uppercase tracking-widest">Findings</p>
            <span className="ml-auto text-[11px] font-mono text-[#5a5a5a] tabular-nums">{analysis.findings.length}</span>
          </div>
          <div className="p-3 space-y-3">
            {(['critical', 'high', 'medium', 'low'] as Severity[]).map(sev => <SeveritySection key={sev} severity={sev} findings={bySev[sev]} folderPath={folderPath} />)}
          </div>
        </div>
      ) : (
        <div className="rounded-xl border border-[#166534]/30 bg-[#166534]/10 p-5 text-center">
          <p className="text-[14px] font-semibold text-[#16a34a]">✓ No findings</p>
          <p className="text-[12px] text-[#3a8a3a] mt-1">AI found no security issues in this codebase.</p>
        </div>
      )}

      {/* Compliance box */}
      {analysis.complianceIssues && analysis.complianceIssues.length > 0 && (
        <div className="rounded-xl border border-[#2a1f0a] bg-[#0f0d00] overflow-hidden">
          <div className="px-4 py-3 border-b border-[#2a1f0a] flex items-center gap-2">
            <svg width="14" height="14" viewBox="0 0 15 15" fill="none" className="shrink-0 text-[#eab308]"><path d="M7.5 1L1 13h13L7.5 1z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round"/><path d="M7.5 6v3.5M7.5 11v.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round"/></svg>
            <p className="text-[11px] font-semibold text-[#eab308] uppercase tracking-widest">Compliance Violations</p>
            <span className="ml-auto text-[11px] font-bold text-[#eab308] bg-[#eab30820] px-2 py-0.5 rounded-full">{analysis.complianceIssues.length}</span>
          </div>
          <div className="divide-y divide-[#1e1800]">
            {analysis.complianceIssues.map((issue, i) => (
              <div key={i} className="px-4 py-3 space-y-1.5">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[11px] font-bold text-[#eab308] bg-[#eab30818] px-2 py-0.5 rounded font-mono">{issue.regulation}</span>
                  {issue.article && <span className="text-[11px] text-[#7a6820] font-mono">{issue.article}</span>}
                </div>
                <p className="text-[12px] text-[#9a8a5a] leading-relaxed">{issue.description}</p>
                <p className="text-[11px] text-[#5a5030] leading-relaxed"><span className="text-[#6a6040] font-semibold">Fix: </span>{issue.recommendation}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Shared: scalability analysis panel
// ---------------------------------------------------------------------------

const SCALE_AREA_CONFIG: Record<string, { label: string; color: string }> = {
  database:     { label: 'Database',     color: '#38bdf8' },
  api:          { label: 'API',          color: '#a78bfa' },
  memory:       { label: 'Memory',       color: '#f472b6' },
  storage:      { label: 'Storage',      color: '#fbbf24' },
  concurrency:  { label: 'Concurrency',  color: '#34d399' },
  architecture: { label: 'Architecture', color: '#94a3b8' }
}

function IconZap(): React.ReactElement {
  return <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>
}

function ScalabilityPanel({ scalability }: { scalability: ScalabilityAssessment }): React.ReactElement {
  const scoreColor = getScoreColor(scalability.scalabilityScore)
  const readiness = scalability.scalabilityScore >= 71 ? 'Scales well' : scalability.scalabilityScore >= 41 ? 'Needs attention' : 'Will not scale'
  const riskOrder: Array<ScalabilityAssessment['bottlenecks'][number]['risk']> = ['critical', 'high', 'medium', 'low']
  const sorted = [...scalability.bottlenecks].sort((a, b) => riskOrder.indexOf(a.risk) - riskOrder.indexOf(b.risk))
  return (
    <div className="rounded-xl border border-[#1e1e1e] bg-[#0f0f0f] overflow-hidden">
      <div className="px-4 py-3 border-b border-[#181818] flex items-center gap-2">
        <span className="text-[#38bdf8]"><IconZap /></span>
        <p className="text-[11px] font-semibold text-[#eeeeee] uppercase tracking-widest">Load Readiness</p>
        <span className="ml-auto text-[11px] font-bold px-2 py-0.5 rounded-full" style={{ color: scoreColor, backgroundColor: scoreColor + '18' }}>{readiness}</span>
      </div>
      <div className="p-4 relative overflow-hidden">
        <div className="absolute -top-6 -right-6 w-28 h-28 rounded-full pointer-events-none" style={{ background: `radial-gradient(circle, ${scoreColor}12 0%, transparent 70%)` }} />
        <div className="flex items-start gap-5">
          <div className="shrink-0"><ScoreCircle score={scalability.scalabilityScore} /></div>
          <p className="flex-1 min-w-0 text-[12px] text-[#8a8a8a] leading-relaxed pt-1">{scalability.summary}</p>
        </div>
      </div>
      {sorted.length > 0 ? (
        <div className="border-t border-[#181818] divide-y divide-[#141414]">
          {sorted.map((b, i) => {
            const cfg = SEVERITY_CONFIG[b.risk] ?? SEVERITY_CONFIG.medium
            const area = SCALE_AREA_CONFIG[b.area] ?? SCALE_AREA_CONFIG.architecture
            return (
              <div key={i} className="px-4 py-3 space-y-1.5">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="px-1.5 py-[2px] rounded text-[9px] font-bold uppercase tracking-wider" style={{ color: cfg.color, border: `1px solid ${cfg.border}` }}>{cfg.label}</span>
                  <span className="px-1.5 py-[2px] rounded text-[9px] font-bold uppercase tracking-wider" style={{ color: area.color, backgroundColor: area.color + '14' }}>{area.label}</span>
                  <p className="text-[12px] font-semibold text-[#eeeeee] flex-1 min-w-0">{b.title}</p>
                </div>
                {b.file && (
                  <p className="text-[10px] font-mono text-[#3a3a3a] truncate">{b.file}{b.line !== null ? `:${b.line}` : ''}</p>
                )}
                {b.explanation && <p className="text-[12px] text-[#8a8a8a] leading-relaxed">{b.explanation}</p>}
                {b.impact && (
                  <div className="rounded-lg border border-[#38bdf8]/15 bg-[#38bdf8]/5 px-3 py-2 space-y-0.5">
                    <p className="text-[9px] uppercase tracking-widest font-semibold text-[#38bdf8]/60">Under load</p>
                    <p className="text-[12px] text-[#9fc8dd] leading-relaxed">{b.impact}</p>
                  </div>
                )}
                {b.recommendation && (
                  <div className="rounded-lg border border-[#5e6ad2]/20 bg-[#5e6ad2]/5 px-3 py-2 space-y-0.5">
                    <p className="text-[9px] uppercase tracking-widest font-semibold text-[#5e6ad2]/60">Fix</p>
                    <p className="text-[12px] text-[#b4b4b4] leading-relaxed">{b.recommendation}</p>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      ) : (
        <div className="border-t border-[#181818] px-4 py-4 text-center">
          <p className="text-[12px] font-medium text-[#16a34a]">✓ No scaling bottlenecks detected in the reviewed code</p>
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Shared: scan history row card
// ---------------------------------------------------------------------------

function ScanHistoryCard({
  entry, onClick, onDelete, showDelete = false
}: {
  entry: ScanHistoryEntry
  onClick: () => void
  onDelete?: (e: React.MouseEvent) => void
  showDelete?: boolean
}): React.ReactElement {
  const scoreColor = getScoreColor(entry.securityScore)
  const total = entry.criticalCount + entry.highCount + entry.mediumCount + entry.lowCount
  const scoreBg = scoreColor === '#16a34a' ? 'rgba(22,163,74,0.1)' : scoreColor === '#eab308' ? 'rgba(234,179,8,0.1)' : 'rgba(239,68,68,0.1)'
  const scoreBorder = scoreColor === '#16a34a' ? 'rgba(22,163,74,0.2)' : scoreColor === '#eab308' ? 'rgba(234,179,8,0.2)' : 'rgba(239,68,68,0.2)'
  return (
    <button
      onClick={onClick}
      className="w-full flex items-center gap-3 px-4 py-3 rounded-xl bg-[#0f0f0f] border border-[#1e1e1e] hover:bg-[#111111] hover:border-[#252525] transition-all text-left group"
    >
      {/* Color-coded score badge */}
      <div className="w-10 h-10 rounded-xl flex flex-col items-center justify-center shrink-0" style={{ background: scoreBg, border: `1px solid ${scoreBorder}` }}>
        <span className="text-[14px] font-bold tabular-nums leading-none" style={{ color: scoreColor }}>{entry.securityScore}</span>
        <span className="text-[8px] font-semibold uppercase tracking-wider mt-0.5" style={{ color: scoreColor, opacity: 0.6 }}>/ 100</span>
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-[13px] font-medium text-[#eeeeee] truncate">{entry.folderName}</p>
        <p className="text-[11px] font-mono text-[#3a3a3a] mt-0.5">{timeAgo(entry.date)} · {formatDateShort(entry.date)}</p>
      </div>
      {/* Severity pills */}
      <div className="flex items-center gap-1.5 shrink-0">
        {entry.criticalCount > 0 && <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-[rgba(239,68,68,0.1)] text-[#ef4444]">{entry.criticalCount}C</span>}
        {entry.highCount > 0 && <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-[rgba(249,115,22,0.1)] text-[#f97316]">{entry.highCount}H</span>}
        {entry.mediumCount > 0 && <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-[rgba(234,179,8,0.1)] text-[#eab308]">{entry.mediumCount}M</span>}
        {total === 0 && <span className="text-[10px] font-medium text-[#16a34a]">✓ clean</span>}
      </div>
      {/* Delete */}
      {showDelete && onDelete && (
        <span
          onClick={onDelete}
          className="shrink-0 p-1.5 rounded-lg text-[#2a2a2a] hover:text-[#ef4444] hover:bg-[#1a0a0a] transition-all opacity-0 group-hover:opacity-100"
        >
          <IconTrash />
        </span>
      )}
    </button>
  )
}

// ---------------------------------------------------------------------------
// Skeleton loading card
// ---------------------------------------------------------------------------

function SkeletonCard(): React.ReactElement {
  return (
    <div className="w-full flex items-center gap-3 px-4 py-3.5 rounded-xl bg-[#0f0f0f] border border-[#1e1e1e]">
      <div className="w-8 h-8 rounded-lg bg-[#161616] animate-pulse shrink-0" />
      <div className="flex-1 space-y-2 min-w-0">
        <div className="h-3 rounded-md bg-[#161616] animate-pulse w-2/5" />
        <div className="h-2.5 rounded-md bg-[#141414] animate-pulse w-1/4" />
      </div>
      <div className="flex gap-1.5 shrink-0">
        <div className="h-4 w-6 rounded bg-[#161616] animate-pulse" />
        <div className="h-4 w-6 rounded bg-[#141414] animate-pulse" />
      </div>
      <div className="w-7 h-5 rounded bg-[#161616] animate-pulse shrink-0" />
    </div>
  )
}

// ---------------------------------------------------------------------------
// "What we scan for" info modal
// ---------------------------------------------------------------------------

const SCAN_CATEGORIES = [
  { label: 'Injection', detail: 'SQL, command, XSS, LDAP, template injection', color: '#ef4444' },
  { label: 'Secrets & Credentials', detail: 'API keys, tokens, passwords, OAuth secrets in code', color: '#eab308' },
  { label: 'Broken Authentication', detail: 'Hardcoded creds, weak session management, JWT flaws', color: '#f97316' },
  { label: 'Insecure Cryptography', detail: 'MD5/SHA1, hardcoded keys, weak random number generators', color: '#a855f7' },
  { label: 'Insecure Deserialization', detail: 'Unsafe pickle/YAML loads, object injection vectors', color: '#3b82f6' },
  { label: 'Path Traversal', detail: 'Directory traversal, unsafe file read/write patterns', color: '#06b6d4' },
  { label: 'SSRF & Open Redirects', detail: 'Unvalidated URLs in HTTP requests, redirect misuse', color: '#84cc16' },
  { label: 'Docker & IaC', detail: 'Root containers, exposed ports, insecure Terraform configs', color: '#6b7280' }
]

function ScanInfoModal({ onClose }: { onClose: () => void }): React.ReactElement {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-6" onClick={onClose}>
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
      <div
        className="relative w-full max-w-md rounded-2xl border border-[#1e1e1e] bg-[#0d0d0d] overflow-hidden animate-fade-in"
        style={{ boxShadow: '0 24px 80px rgba(0,0,0,0.7)' }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="px-5 py-4 border-b border-[#181818] flex items-center justify-between">
          <div>
            <p className="text-[13px] font-semibold text-[#eeeeee]">What Snagify scans for</p>
            <p className="text-[11px] text-[#3a3a3a] mt-0.5">Powered by Semgrep + Gitleaks + OSV + Claude AI</p>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg text-[#3a3a3a] hover:text-[#eeeeee] hover:bg-[#1a1a1a] transition-all">
            <IconX />
          </button>
        </div>
        {/* Categories */}
        <div className="px-5 py-4 space-y-3 max-h-[400px] overflow-y-auto">
          {SCAN_CATEGORIES.map(cat => (
            <div key={cat.label} className="flex items-start gap-3">
              <span className="w-2 h-2 rounded-full shrink-0 mt-[5px]" style={{ backgroundColor: cat.color }} />
              <div className="min-w-0">
                <p className="text-[12px] font-semibold text-[#c4c4c4]">{cat.label}</p>
                <p className="text-[11px] text-[#4a4a4a] leading-snug mt-0.5">{cat.detail}</p>
              </div>
            </div>
          ))}
        </div>
        {/* Footer */}
        <div className="px-5 py-3 border-t border-[#181818] bg-[#0a0a0a]">
          <p className="text-[10px] text-[#2a2a2a] leading-relaxed">
            Semgrep checks code for vulnerabilities using 1,000+ open-source rules.
            Gitleaks detects secrets using entropy analysis and pattern matching.
            OSV checks dependencies against Google&apos;s open vulnerability database.
            Claude AI consolidates findings and provides fix suggestions.
          </p>
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Dashboard recharts components
// ---------------------------------------------------------------------------

interface ChartPoint { date: string; score: number; name: string }

function ChartTooltip({ active, payload }: { active?: boolean; payload?: Array<{ payload: ChartPoint }> }): React.ReactElement | null {
  if (!active || !payload?.length) return null
  const d = payload[0].payload
  const c = getScoreColor(d.score)
  return (
    <div className="px-3 py-2.5 rounded-xl bg-[#0d0d0d] border border-[#252525]" style={{ boxShadow: '0 8px 24px rgba(0,0,0,0.6)' }}>
      <p className="text-[10px] font-mono text-[#4a4a4a]">{d.date}</p>
      <p className="text-[20px] font-bold leading-tight tabular-nums" style={{ color: c }}>{d.score}<span className="text-[11px] font-normal text-[#3a3a3a] ml-1">/ 100</span></p>
      <p className="text-[11px] text-[#5a5a5a] max-w-[140px] truncate">{d.name}</p>
    </div>
  )
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function ScoreDot(props: any): React.ReactElement {
  const { cx, cy, payload } = props as { cx: number; cy: number; payload: ChartPoint }
  return <circle cx={cx} cy={cy} r={4} fill={getScoreColor(payload.score)} stroke="#0a0a0a" strokeWidth={2} />
}

// ---------------------------------------------------------------------------
// Dashboard view
// ---------------------------------------------------------------------------

function DashboardView({ onNavigate }: { onNavigate: (nav: NavItem) => void }): React.ReactElement {
  const [history, setHistory] = useState<ScanHistoryEntry[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    window.api.getScanHistory().then(h => { setHistory(h); setLoading(false) })
  }, [])

  if (loading) {
    return (
      <div className="flex-1 overflow-y-auto px-6 py-5 space-y-4">
        <div className="h-[148px] rounded-2xl bg-[#0f0f0f] border border-[#1e1e1e] animate-pulse" />
        <div className="grid grid-cols-4 gap-3">
          {[0,1,2,3].map(i => <div key={i} className="h-[80px] rounded-xl bg-[#0f0f0f] border border-[#1e1e1e] animate-pulse" style={{ animationDelay: `${i*60}ms` }} />)}
        </div>
        <div className="h-[210px] rounded-xl bg-[#0f0f0f] border border-[#1e1e1e] animate-pulse" />
        <div className="space-y-2">{[0,1,2].map(i => <SkeletonCard key={i} />)}</div>
      </div>
    )
  }

  // Empty state
  if (!history.length) {
    return (
      <div className="flex-1 flex flex-col overflow-hidden">
        <div className="flex-1 flex flex-col items-center justify-center gap-7 px-8 relative">
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
            <div className="w-72 h-72 rounded-full" style={{ background: 'radial-gradient(circle, rgba(94,106,210,0.05) 0%, transparent 70%)' }} />
          </div>
          <div className="relative z-10 flex flex-col items-center text-center gap-6 max-w-[320px]">
            <div className="w-16 h-16 rounded-2xl bg-[#111111] border border-[#1e1e1e] flex items-center justify-center">
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" className="text-[#5e6ad2]"><path d="M12 2L4 6V12C4 16.4183 7.58172 20.4 12 22C16.4183 20.4 20 16.4183 20 12V6L12 2Z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>
            </div>
            <div className="space-y-2">
              <h2 className="text-[17px] font-bold text-[#eeeeee] tracking-tight">Secure your first project</h2>
              <p className="text-[12px] text-[#4a4a4a] leading-relaxed">Drop a folder to scan for vulnerabilities, exposed secrets, and compliance issues with Semgrep + Gitleaks + OSV + Claude AI.</p>
            </div>
            <div className="grid grid-cols-4 gap-2 w-full">
              {[
                { label: 'Semgrep', desc: '1,000+ rules', dot: '#5e6ad2' },
                { label: 'Gitleaks', desc: 'Secret detection', dot: '#eab308' },
                { label: 'OSV', desc: 'Dependency CVEs', dot: '#a78bfa' },
                { label: 'Claude AI', desc: 'Fix suggestions', dot: '#84cc16' },
              ].map(f => (
                <div key={f.label} className="flex flex-col items-center gap-1.5 px-2 py-3 rounded-xl bg-[#0f0f0f] border border-[#1e1e1e]">
                  <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: f.dot }} />
                  <p className="text-[11px] font-semibold text-[#c4c4c4]">{f.label}</p>
                  <p className="text-[9px] text-[#3a3a3a] text-center">{f.desc}</p>
                </div>
              ))}
            </div>
            <button
              onClick={() => onNavigate('new-scan')}
              className="w-full py-3.5 rounded-xl text-white text-[13px] font-semibold flex items-center justify-center gap-2.5 bg-[#5e6ad2] hover:bg-[#6b77df] transition-colors active:scale-[0.99]"
              style={{ boxShadow: '0 0 28px rgba(94,106,210,0.2)' }}
            >
              <IconPlay />Start First Scan
            </button>
          </div>
        </div>
      </div>
    )
  }

  // Derived stats
  const latest = history[0]
  const avgScore = Math.round(history.reduce((s, e) => s + e.securityScore, 0) / history.length)
  const totalCritical = history.reduce((s, e) => s + e.criticalCount, 0)
  const totalHigh = history.reduce((s, e) => s + e.highCount, 0)
  const latestColor = getScoreColor(latest.securityScore)

  // Chart data — oldest first, max 10
  const chartData: ChartPoint[] = history.slice(0, 10).reverse().map(e => ({
    date: formatDateShort(e.date),
    score: e.securityScore,
    name: e.folderName
  }))
  const scoreTrend = chartData.length >= 2 ? chartData[chartData.length - 1].score - chartData[0].score : 0

  return (
    <div className="flex-1 overflow-y-auto px-6 py-5 space-y-4">

      {/* Latest scan hero */}
      <div className="rounded-2xl border border-[#1e1e1e] bg-[#0f0f0f] p-5 relative overflow-hidden">
        {/* Ambient glow matching score */}
        <div className="absolute -top-8 -right-8 w-36 h-36 rounded-full pointer-events-none" style={{ background: `radial-gradient(circle, ${latestColor}18 0%, transparent 70%)` }} />
        <div className="flex items-center gap-5">
          <div className="shrink-0"><ScoreCircle score={latest.securityScore} /></div>
          <div className="flex-1 min-w-0">
            <p className="text-[10px] text-[#3a3a3a] uppercase tracking-widest font-semibold mb-1">Latest Scan</p>
            <p className="text-[15px] font-bold text-[#eeeeee] truncate">{latest.folderName}</p>
            <p className="text-[11px] font-mono text-[#4a4a4a] mt-0.5">{timeAgo(latest.date)} · {formatDate(latest.date)}</p>
            <div className="flex items-center gap-3 mt-2.5">
              {latest.criticalCount > 0 && <span className="flex items-center gap-1 text-[11px]"><span className="font-bold text-[#ef4444]">{latest.criticalCount}</span><span className="text-[#4a3a3a]">critical</span></span>}
              {latest.highCount > 0 && <span className="flex items-center gap-1 text-[11px]"><span className="font-bold text-[#f97316]">{latest.highCount}</span><span className="text-[#4a4a3a]">high</span></span>}
              {latest.mediumCount > 0 && <span className="flex items-center gap-1 text-[11px]"><span className="font-bold text-[#eab308]">{latest.mediumCount}</span><span className="text-[#4a4a3a]">medium</span></span>}
              {(latest.criticalCount + latest.highCount + latest.mediumCount + latest.lowCount === 0) && (
                <span className="text-[11px] font-semibold text-[#16a34a]">✓ Clean scan</span>
              )}
            </div>
          </div>
          <div className="shrink-0 flex flex-col gap-2">
            <button onClick={() => onNavigate('new-scan')} className="px-4 py-2.5 rounded-lg text-[13px] font-semibold text-white bg-[#5e6ad2] hover:bg-[#6b77df] transition-colors flex items-center justify-center gap-1.5">
              <IconPlay />New Scan
            </button>
            <button onClick={() => onNavigate('history')} className="px-4 py-2 rounded-lg text-[12px] font-medium text-[#5a5a5a] border border-[#222222] hover:border-[#333333] hover:text-[#c4c4c4] transition-all text-center">
              All history
            </button>
          </div>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Total Scans', value: String(history.length), accent: '#5e6ad2', sub: `${history.length} project${history.length !== 1 ? 's' : ''}` },
          { label: 'Avg Score', value: String(avgScore), accent: getScoreColor(avgScore), sub: avgScore >= 71 ? 'Good posture' : avgScore >= 41 ? 'Needs attention' : 'Critical risk' },
          { label: 'Criticals', value: String(totalCritical), accent: totalCritical > 0 ? '#ef4444' : '#16a34a', sub: totalCritical === 0 ? 'None detected' : `Across ${history.filter(e => e.criticalCount > 0).length} scan${history.filter(e => e.criticalCount > 0).length !== 1 ? 's' : ''}` },
          { label: 'High Issues', value: String(totalHigh), accent: totalHigh > 0 ? '#f97316' : '#16a34a', sub: totalHigh === 0 ? 'None detected' : 'Total across all' },
        ].map(({ label, value, accent, sub }) => (
          <div key={label} className="flex flex-col gap-2 px-4 py-3.5 rounded-xl bg-[#0f0f0f] border border-[#1e1e1e]">
            <span className="text-[10px] text-[#3a3a3a] uppercase tracking-widest font-semibold">{label}</span>
            <span className="text-[24px] font-bold leading-none tracking-tight tabular-nums" style={{ color: accent }}>{value}</span>
            <span className="text-[10px] text-[#3a3a3a] leading-snug">{sub}</span>
          </div>
        ))}
      </div>

      {/* Score trend chart — only show if 2+ scans */}
      {chartData.length >= 2 && (
        <div className="rounded-xl border border-[#1e1e1e] bg-[#0f0f0f] overflow-hidden">
          <div className="px-4 py-3 border-b border-[#181818] flex items-center justify-between">
            <div>
              <p className="text-[13px] font-semibold text-[#c4c4c4]">Score Trend</p>
              <p className="text-[11px] text-[#3a3a3a] mt-0.5">Last {chartData.length} scans</p>
            </div>
            <span className={`flex items-center gap-1 text-[12px] font-bold px-2.5 py-1 rounded-lg ${scoreTrend >= 0 ? 'text-[#16a34a] bg-[#16a34a]/10' : 'text-[#ef4444] bg-[#ef4444]/10'}`}>
              {scoreTrend >= 0 ? '↑' : '↓'} {Math.abs(scoreTrend)} pts
            </span>
          </div>
          <div className="px-2 pt-4 pb-2" style={{ height: 188 }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 4, right: 16, bottom: 4, left: 0 }}>
                <defs>
                  <linearGradient id="scoreAreaGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#5e6ad2" stopOpacity={0.2} />
                    <stop offset="100%" stopColor="#5e6ad2" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#161616" strokeDasharray="0" vertical={false} />
                <XAxis dataKey="date" tick={{ fill: '#3a3a3a', fontSize: 10, fontFamily: 'monospace' }} axisLine={{ stroke: '#1e1e1e' }} tickLine={false} />
                <YAxis domain={[0, 100]} tick={{ fill: '#3a3a3a', fontSize: 10 }} axisLine={false} tickLine={false} width={28} ticks={[0, 25, 50, 75, 100]} />
                <Tooltip content={<ChartTooltip />} cursor={{ stroke: '#2a2a2a', strokeWidth: 1 }} />
                <Area type="monotone" dataKey="score" stroke="#5e6ad2" strokeWidth={2} fill="url(#scoreAreaGrad)" dot={<ScoreDot />} activeDot={{ r: 6, fill: '#7b87e5', stroke: '#0a0a0a', strokeWidth: 2 }} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Recent scans */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <p className="text-[12px] font-semibold text-[#5a5a5a]">Recent Scans</p>
          <button onClick={() => onNavigate('history')} className="text-[11px] text-[#5e6ad2] hover:text-[#7b87e5] transition-colors">View all →</button>
        </div>
        {history.slice(0, 4).map(entry => (
          <ScanHistoryCard key={entry.id} entry={entry} onClick={() => onNavigate('history')} />
        ))}
      </div>

      <div className="h-2" />
    </div>
  )
}

// ---------------------------------------------------------------------------
// History scan detail view
// ---------------------------------------------------------------------------

function HistoryScanDetailView({
  entry, onBack, onDelete
}: {
  entry: ScanHistoryEntry
  onBack: () => void
  onDelete: () => void
}): React.ReactElement {
  const [confirmDelete, setConfirmDelete] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [toast, setToast] = useState<ToastState | null>(null)
  const [exporting, setExporting] = useState(false)
  const [copying, setCopying] = useState(false)

  const analysis: AnalysisResult = {
    securityScore: entry.securityScore,
    summary: entry.summary,
    criticalCount: entry.criticalCount,
    highCount: entry.highCount,
    mediumCount: entry.mediumCount,
    lowCount: entry.lowCount,
    findings: entry.findings,
    scalability: entry.scalability
  }

  const handleDelete = useCallback(async (): Promise<void> => {
    setDeleting(true)
    try {
      await window.api.deleteScan(entry.id)
      onDelete()
    } finally { setDeleting(false) }
  }, [entry.id, onDelete])

  const handleExportPdf = useCallback(async (): Promise<void> => {
    if (exporting) return
    setExporting(true)
    try {
      const data = buildPdfReport(analysis, entry.folderName, entry.folderPath)
      const safeName = entry.folderName.replace(/[^a-zA-Z0-9-_]/g, '-')
      const dateSlug = entry.date.slice(0, 10)
      const filename = `snagify-report-${safeName}-${dateSlug}.pdf`
      await window.api.savePdfReport(filename, data)
      setToast({ message: `Saved ${filename}`, type: 'success' })
    } catch (err) {
      setToast({ message: String(err), type: 'error' })
    } finally {
      setExporting(false)
    }
  }, [analysis, entry, exporting])

  const handleCopySummary = useCallback(async (): Promise<void> => {
    if (copying) return
    setCopying(true)
    try {
      await navigator.clipboard.writeText(buildShareableSummary(analysis, entry.folderName))
      setToast({ message: 'Summary copied to clipboard', type: 'success' })
    } catch {
      setToast({ message: 'Failed to copy', type: 'error' })
    } finally {
      setTimeout(() => setCopying(false), 1200)
    }
  }, [analysis, entry.folderName, copying])

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      {toast && <Toast toast={toast} onDismiss={() => setToast(null)} />}
      {/* Header */}
      <div className="shrink-0 px-6 py-3.5 border-b border-[#181818] flex items-center gap-3">
        <button onClick={onBack} className="flex items-center gap-1.5 text-[12px] font-medium text-[#5a5a5a] hover:text-[#eeeeee] transition-colors">
          <IconArrowLeft />Back
        </button>
        <div className="h-3 w-px bg-[#222222]" />
        <div className="flex-1 min-w-0">
          <p className="text-[13px] font-semibold text-[#eeeeee] truncate">{entry.folderName}</p>
          <p className="text-[10px] font-mono text-[#3a3a3a]">{formatDateTime(entry.date)}</p>
        </div>
        {/* Export / Copy */}
        <button onClick={handleExportPdf} disabled={exporting} title="Export PDF" className="shrink-0 p-1.5 rounded-lg text-[#3a3a3a] hover:text-[#eeeeee] hover:bg-[#1a1a1a] disabled:opacity-40 transition-all">
          {exporting ? <div className="w-3.5 h-3.5 rounded-full border border-[#3a3a3a] border-t-[#eeeeee] animate-spin" /> : <IconDownload />}
        </button>
        <button onClick={handleCopySummary} disabled={copying} title="Copy summary" className="shrink-0 p-1.5 rounded-lg text-[#3a3a3a] hover:text-[#eeeeee] hover:bg-[#1a1a1a] transition-all">
          {copying ? <span className="text-[#16a34a]"><IconCheck /></span> : <IconCopy />}
        </button>
        {/* Delete */}
        {!confirmDelete ? (
          <button onClick={() => setConfirmDelete(true)} className="shrink-0 p-1.5 rounded-lg text-[#3a3a3a] hover:text-[#ef4444] hover:bg-[#150a0a] transition-all"><IconTrash /></button>
        ) : (
          <div className="flex items-center gap-2 shrink-0">
            <span className="text-[11px] text-[#8a8a8a]">Delete?</span>
            <button onClick={() => setConfirmDelete(false)} className="px-2.5 py-1 rounded-lg text-[11px] font-medium text-[#5a5a5a] border border-[#222222] hover:border-[#333333] transition-all">Cancel</button>
            <button onClick={handleDelete} disabled={deleting} className="px-2.5 py-1 rounded-lg text-[11px] font-semibold text-white bg-[#ef4444] hover:bg-[#dc2626] disabled:opacity-40 transition-colors">{deleting ? '…' : 'Delete'}</button>
          </div>
        )}
      </div>

      <div className="flex-1 overflow-y-auto px-6 py-5 space-y-4">
        {/* Folder path */}
        <div className="rounded-xl border border-[#1e1e1e] bg-[#0f0f0f] px-4 py-3 flex items-center gap-2.5">
          <span className="text-[#3a3a3a] shrink-0"><IconFolder size={14} /></span>
          <p className="text-[11px] font-mono text-[#4a4a4a] truncate">{entry.folderPath}</p>
        </div>

        <SectionLabel text="AI Security Analysis" />
        <AIAnalysisPanel analysis={analysis} folderPath={entry.folderPath} />
        {analysis.scalability && <><SectionLabel text="Scalability Analysis" /><ScalabilityPanel scalability={analysis.scalability} /></>}
        <div className="h-1" />
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// History view
// ---------------------------------------------------------------------------

function HistoryView(): React.ReactElement {
  const [history, setHistory] = useState<ScanHistoryEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<ScanHistoryEntry | null>(null)

  const reload = useCallback((): void => {
    window.api.getScanHistory().then(h => { setHistory(h); setLoading(false) })
  }, [])

  useEffect(() => { reload() }, [reload])

  const handleDelete = useCallback((id: string): void => {
    setHistory(prev => prev.filter(e => e.id !== id))
    if (selected?.id === id) setSelected(null)
  }, [selected])

  // List rows carry metadata only — fetch the full entry (findings + scalability) on open
  const handleOpen = useCallback(async (entry: ScanHistoryEntry): Promise<void> => {
    try {
      const full = await window.api.getScanById(entry.id)
      setSelected(full ?? entry)
    } catch {
      setSelected(entry)
    }
  }, [])

  if (selected) {
    return (
      <HistoryScanDetailView
        entry={selected}
        onBack={() => setSelected(null)}
        onDelete={() => { handleDelete(selected.id); setSelected(null) }}
      />
    )
  }

  if (loading) {
    return (
      <div className="flex-1 overflow-y-auto px-6 py-5 space-y-2">
        <div className="h-3 w-20 rounded bg-[#161616] animate-pulse mb-3" />
        {[0,1,2,3,4].map(i => <SkeletonCard key={i} />)}
      </div>
    )
  }

  if (!history.length) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center gap-4 px-8">
        <div className="w-10 h-10 rounded-xl bg-[#111111] border border-[#1e1e1e] flex items-center justify-center text-[#2a2a2a]"><IconHistory /></div>
        <p className="text-[13px] font-medium text-[#3a3a3a]">No scan history yet</p>
      </div>
    )
  }

  return (
    <div className="flex-1 overflow-y-auto px-6 py-5 space-y-2">
      <div className="flex items-center justify-between mb-1">
        <p className="text-[10px] text-[#3a3a3a] uppercase tracking-widest font-semibold">{history.length} scan{history.length !== 1 ? 's' : ''}</p>
      </div>
      {history.map(entry => (
        <ScanHistoryCard
          key={entry.id}
          entry={entry}
          onClick={() => handleOpen(entry)}
          showDelete
          onDelete={async (e) => {
            e.stopPropagation()
            await window.api.deleteScan(entry.id)
            setHistory(prev => prev.filter(h => h.id !== entry.id))
          }}
        />
      ))}
      <div className="h-1" />
    </div>
  )
}

// ---------------------------------------------------------------------------
// File tree
// ---------------------------------------------------------------------------

function FileTreeEntry({ node, depth }: { node: TreeNode; depth: number }): React.ReactElement {
  const [open, setOpen] = useState(depth < 1)
  const indent = depth * 14
  if (node.type === 'dir') {
    return (
      <div>
        <button onClick={() => setOpen(v => !v)} style={{ paddingLeft: `${4 + indent}px` }} className="w-full flex items-center gap-1.5 py-[3px] pr-3 hover:bg-[#161616] rounded group transition-colors">
          <span className="text-[#3a3a3a] shrink-0" style={{ transform: open ? 'rotate(90deg)' : 'rotate(0deg)', display: 'inline-flex', transition: 'transform 0.1s' }}><IconChevronRight /></span>
          <span className="text-[#5e6ad2] shrink-0"><IconFolder size={12} /></span>
          <span className="text-[12px] font-mono text-[#c4c4c4] truncate flex-1 text-left">{node.name}</span>
          {node.children && <span className="text-[10px] font-mono text-[#333333] shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">{node.children.length}</span>}
        </button>
        {open && node.children && <div>{node.children.map((child, i) => <FileTreeEntry key={i} node={child} depth={depth + 1} />)}</div>}
      </div>
    )
  }
  return (
    <div style={{ paddingLeft: `${18 + indent}px` }} className="flex items-center gap-1.5 py-[3px] pr-3 hover:bg-[#161616] rounded transition-colors">
      <span style={{ color: getFileColor(node.name) }} className="shrink-0"><IconFile /></span>
      <span className="text-[12px] font-mono text-[#5a5a5a] truncate">{node.name}</span>
    </div>
  )
}

function LoadingView({ path }: { path: string }): React.ReactElement {
  return (
    <div className="flex-1 flex flex-col items-center justify-center gap-5 px-8">
      <div className="flex gap-1.5">{[0,1,2].map(i => <div key={i} className="w-1.5 h-1.5 rounded-full bg-[#5e6ad2] animate-pulse" style={{ animationDelay: `${i * 180}ms` }} />)}</div>
      <div className="text-center space-y-1.5">
        <p className="text-[13px] font-medium text-[#c4c4c4]">Analyzing project…</p>
        <p className="text-[11px] font-mono text-[#4a4a4a] max-w-sm truncate" title={path}>{path}</p>
      </div>
    </div>
  )
}

function StatPill({ label, value, accent }: { label: string; value: string; accent?: string }): React.ReactElement {
  return (
    <div className="flex flex-col gap-1.5 px-4 py-3.5 rounded-xl bg-[#0f0f0f] border border-[#1e1e1e]">
      <span className="text-[10px] text-[#3a3a3a] uppercase tracking-widest font-semibold">{label}</span>
      <span className="text-[22px] font-bold leading-none tracking-tight tabular-nums" style={{ color: accent ?? '#f0f0f0' }}>{value}</span>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Scanning view
// ---------------------------------------------------------------------------

function ScanningView({ folderPath, progress, isCancelling, onCancel }: {
  folderPath: string; progress: ScanProgress | null; isCancelling: boolean; onCancel: () => void
}): React.ReactElement {
  const folderName = folderPath.replace(/\\/g, '/').split('/').filter(Boolean).pop() ?? folderPath
  const activeIdx = getActiveStepIndex(progress?.step)
  const isDone = progress?.step === 'done'
  const isCancelled = progress?.step === 'cancelled'
  return (
    <div className="flex-1 flex flex-col items-center justify-center px-8">
      <div className="w-full max-w-sm space-y-8">
        <div className="space-y-1">
          <p className="text-[13px] font-semibold text-[#eeeeee] tracking-tight">{isCancelled ? 'Scan cancelled' : isDone ? 'Scan complete' : 'Scanning project…'}</p>
          <p className="text-[11px] font-mono text-[#3a3a3a] truncate" title={folderPath}>{folderName}</p>
        </div>
        <div className="space-y-3">
          {SCAN_STEPS.map((step, i) => {
            const state = getStepDisplayState(i, activeIdx, progress?.step)
            return (
              <div key={step.id} className="flex items-start gap-3">
                <div className="w-5 h-5 flex items-center justify-center shrink-0 mt-[1px]">
                  {state === 'done' && <div className="w-5 h-5 rounded-full bg-[#166534]/30 border border-[#16a34a]/40 flex items-center justify-center text-[#16a34a]"><IconCheck /></div>}
                  {state === 'active' && <div className="relative flex items-center justify-center w-5 h-5"><div className="w-2 h-2 rounded-full bg-[#5e6ad2] z-10" /><div className="absolute w-2 h-2 rounded-full bg-[#5e6ad2] animate-ping opacity-60" /></div>}
                  {state === 'error' && <div className="w-5 h-5 rounded-full bg-[#7f1d1d]/30 border border-[#ef4444]/30 flex items-center justify-center text-[#ef4444]"><IconX /></div>}
                  {state === 'skipped' && <div className="w-5 h-5 rounded-full bg-[#1c1c1c] border border-[#2a2a2a] flex items-center justify-center"><span className="text-[#3a3a3a]">—</span></div>}
                  {state === 'pending' && <div className="w-5 h-5 rounded-full border border-[#252525] flex items-center justify-center"><div className="w-1.5 h-1.5 rounded-full bg-[#2a2a2a]" /></div>}
                </div>
                <div className="flex-1 min-w-0 pt-[2px]">
                  <p className={`text-[13px] font-medium leading-tight ${state === 'done' ? 'text-[#5a5a5a]' : state === 'active' ? 'text-[#eeeeee]' : state === 'error' ? 'text-[#f87171]' : state === 'skipped' ? 'text-[#4a4a4a]' : 'text-[#2a2a2a]'}`}>
                    {step.label}{state === 'skipped' && <span className="ml-2 text-[10px] font-mono text-[#3a3a3a] uppercase tracking-wider">skipped</span>}
                  </p>
                  {state === 'active' && progress?.message && <p className="text-[11px] font-mono text-[#4a4a4a] mt-0.5 truncate">{progress.message}</p>}
                  {state === 'error' && progress?.message && <p className="text-[11px] font-mono text-[#f87171]/60 mt-0.5 truncate">{progress.message}</p>}
                </div>
              </div>
            )
          })}
        </div>
        <div className="h-px bg-[#181818]" />
        {!isDone && !isCancelled && (
          <button onClick={onCancel} disabled={isCancelling} className="w-full py-2.5 rounded-lg text-[13px] font-medium text-[#5a5a5a] hover:text-[#c4c4c4] border border-[#222222] hover:border-[#333333] bg-transparent hover:bg-[#111111] transition-all disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2">
            <IconX />{isCancelling ? 'Cancelling…' : 'Cancel scan'}
          </button>
        )}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Scan result view
// ---------------------------------------------------------------------------

function ScanResultView({ result, folderPath, onBack, onNewScan }: {
  result: ScanResult; folderPath: string; onBack: () => void; onNewScan: () => void
}): React.ReactElement {
  const folderName = folderPath.replace(/\\/g, '/').split('/').filter(Boolean).pop() ?? folderPath
  const osvFindings = result.osvFindings ?? []
  const totalFindings = result.semgrepFindings.length + result.gitleaksFindings.length + osvFindings.length
  const [toast, setToast] = useState<ToastState | null>(null)
  const [exporting, setExporting] = useState(false)
  const [copying, setCopying] = useState(false)
  const [depsOpen, setDepsOpen] = useState(false)
  const [ignoredOpen, setIgnoredOpen] = useState(false)
  const [suppressions, setSuppressions] = useState<SuppressedFinding[]>([])

  useEffect(() => {
    window.api.getSuppressions(folderPath).then(setSuppressions).catch(() => { /* none */ })
  }, [folderPath])

  const handleToggleIgnored = useCallback(async (): Promise<void> => {
    if (!ignoredOpen) {
      try { setSuppressions(await window.api.getSuppressions(folderPath)) } catch { /* keep stale */ }
    }
    setIgnoredOpen(o => !o)
  }, [ignoredOpen, folderPath])

  const handleRestoreSuppression = useCallback(async (key: string): Promise<void> => {
    try { setSuppressions(await window.api.unsuppressFinding(folderPath, key)) } catch { /* keep */ }
  }, [folderPath])

  const handleExportPdf = useCallback(async (): Promise<void> => {
    if (!result.analysis || exporting) return
    setExporting(true)
    try {
      const data = buildPdfReport(result.analysis, folderName, folderPath)
      const safeName = folderName.replace(/[^a-zA-Z0-9-_]/g, '-')
      const dateSlug = new Date().toISOString().slice(0, 10)
      const filename = `snagify-report-${safeName}-${dateSlug}.pdf`
      await window.api.savePdfReport(filename, data)
      setToast({ message: `Saved ${filename}`, type: 'success' })
    } catch (err) {
      setToast({ message: String(err), type: 'error' })
    } finally {
      setExporting(false)
    }
  }, [result.analysis, folderName, folderPath, exporting])

  const handleCopySummary = useCallback(async (): Promise<void> => {
    if (!result.analysis || copying) return
    setCopying(true)
    try {
      await navigator.clipboard.writeText(buildShareableSummary(result.analysis, folderName))
      setToast({ message: 'Summary copied to clipboard', type: 'success' })
    } catch {
      setToast({ message: 'Failed to copy', type: 'error' })
    } finally {
      setTimeout(() => setCopying(false), 1200)
    }
  }, [result.analysis, folderName, copying])

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      {toast && <Toast toast={toast} onDismiss={() => setToast(null)} />}
      <div className="flex-1 overflow-y-auto px-6 py-5 space-y-4">
        <SectionLabel text="Overview" />
        <div className="rounded-xl border border-[#1e1e1e] bg-[#0f0f0f] overflow-hidden">
          <div className="px-4 py-3.5 border-b border-[#181818] flex items-center gap-3">
            <div className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 border ${totalFindings > 0 ? 'bg-[#7f1d1d]/20 border-[#ef4444]/20 text-[#ef4444]' : 'bg-[#166534]/20 border-[#16a34a]/20 text-[#16a34a]'}`}><IconShield /></div>
            <div className="flex-1 min-w-0">
              <p className="text-[14px] font-semibold text-[#f0f0f0] tracking-tight">{totalFindings > 0 ? `${totalFindings} finding${totalFindings !== 1 ? 's' : ''} detected` : 'No findings detected'}</p>
              <p className="text-[11px] font-mono text-[#3a3a3a] truncate mt-0.5" title={folderPath}>{folderName}</p>
            </div>
          </div>
          {result.comparison && (() => {
            const c = result.comparison
            const prevDateLabel = new Date(c.prevDate).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
            const deltaColor = c.scoreDelta > 0 ? '#16a34a' : c.scoreDelta < 0 ? '#ef4444' : '#5a5a5a'
            return (
              <div className="px-4 py-3 border-b border-[#181818] flex items-center gap-3 flex-wrap bg-[#0c0c0c]">
                <span className="text-[10px] text-[#3a3a3a] uppercase tracking-widest font-semibold shrink-0">vs last scan · {prevDateLabel}</span>
                <div className="flex items-center gap-2 flex-1 justify-end flex-wrap">
                  {c.fixedCount > 0 && (
                    <span className="flex items-center gap-1 px-2 py-1 rounded-full bg-[#166534]/15 border border-[#166534]/30 text-[11px] font-semibold text-[#16a34a]"><IconCheck />{c.fixedCount} fixed</span>
                  )}
                  {c.newCount > 0 && (
                    <span className="flex items-center gap-1 px-2 py-1 rounded-full bg-[#7f1d1d]/15 border border-[#ef4444]/25 text-[11px] font-semibold text-[#ef4444]">{c.newCount} new</span>
                  )}
                  {c.fixedCount === 0 && c.newCount === 0 && (
                    <span className="px-2 py-1 rounded-full bg-[#141414] border border-[#222222] text-[11px] font-medium text-[#5a5a5a]">No change in findings</span>
                  )}
                  <span className="px-2 py-1 rounded-full text-[11px] font-bold tabular-nums" style={{ color: deltaColor, backgroundColor: deltaColor + '15', border: `1px solid ${deltaColor}30` }}>
                    {c.scoreDelta > 0 ? '+' : ''}{c.scoreDelta} pts
                  </span>
                </div>
              </div>
            )
          })()}
          <div className="grid grid-cols-3 divide-x divide-[#181818]">
            <div className="flex flex-col gap-1.5 px-4 py-3.5">
              <div className="flex items-center gap-2"><span className="text-[#f97316]"><IconShield /></span><span className="text-[10px] text-[#3a3a3a] uppercase tracking-widest font-semibold">Code</span></div>
              <span className={`text-[22px] font-bold leading-none tracking-tight tabular-nums ${result.semgrepFindings.length > 0 ? 'text-[#f97316]' : 'text-[#f0f0f0]'}`}>{result.semgrepFindings.length}</span>
            </div>
            <div className="flex flex-col gap-1.5 px-4 py-3.5">
              <div className="flex items-center gap-2"><span className="text-[#eab308]"><IconKey /></span><span className="text-[10px] text-[#3a3a3a] uppercase tracking-widest font-semibold">Secrets</span></div>
              <span className={`text-[22px] font-bold leading-none tracking-tight tabular-nums ${result.gitleaksFindings.length > 0 ? 'text-[#eab308]' : 'text-[#f0f0f0]'}`}>{result.gitleaksFindings.length}</span>
            </div>
            <div className="flex flex-col gap-1.5 px-4 py-3.5">
              <div className="flex items-center gap-2"><span className="text-[#a78bfa]"><IconPackage /></span><span className="text-[10px] text-[#3a3a3a] uppercase tracking-widest font-semibold">Deps</span></div>
              <span className={`text-[22px] font-bold leading-none tracking-tight tabular-nums ${osvFindings.length > 0 ? 'text-[#a78bfa]' : 'text-[#f0f0f0]'}`}>{osvFindings.length}</span>
            </div>
          </div>
        </div>
        {result.analysis && <><SectionLabel text="AI Security Analysis" /><AIAnalysisPanel analysis={result.analysis} folderPath={folderPath} /></>}
        {result.analysis?.scalability && <><SectionLabel text="Scalability Analysis" /><ScalabilityPanel scalability={result.analysis.scalability} /></>}
        {osvFindings.length > 0 && (
          <>
          <SectionLabel text="Vulnerable Dependencies" />
          <div className="rounded-xl border border-[#1e1e1e] bg-[#0f0f0f] overflow-hidden">
            <button onClick={() => setDepsOpen(o => !o)} className="w-full px-4 py-3 flex items-center gap-2.5 hover:bg-[#131313] transition-colors">
              <span className="text-[#a78bfa]"><IconPackage /></span>
              <span className="text-[12px] font-semibold text-[#eeeeee] flex-1 text-left">{osvFindings.length} package{osvFindings.length !== 1 ? 's' : ''} with known CVEs</span>
              <span className="text-[11px] font-mono text-[#a78bfa] tabular-nums">{depsOpen ? 'Hide' : 'Show'}</span>
              <span className={`text-[#3a3a3a] transition-transform ${depsOpen ? 'rotate-180' : ''}`}><IconChevronDown /></span>
            </button>
            {depsOpen && (
              <div className="border-t border-[#181818] divide-y divide-[#141414] max-h-[320px] overflow-y-auto">
                {osvFindings.map((f, i) => {
                  const cve = f.aliases.find(a => a.startsWith('CVE-')) ?? f.ids[0]
                  const sevColor = (f.cvss ?? 0) >= 9 ? '#ef4444' : (f.cvss ?? 0) >= 7 ? '#f97316' : (f.cvss ?? 0) >= 4 ? '#eab308' : '#6b7280'
                  return (
                    <div key={i} className="px-4 py-2.5 flex items-start gap-3">
                      <span className="shrink-0 mt-0.5 px-1.5 py-0.5 rounded text-[10px] font-bold font-mono tabular-nums" style={{ color: sevColor, backgroundColor: sevColor + '18' }}>{f.cvss?.toFixed(1) ?? '—'}</span>
                      <div className="flex-1 min-w-0">
                        <p className="text-[12px] font-medium text-[#d4d4d4] truncate">
                          <span className="font-mono">{f.package}@{f.version}</span>
                          <span className="text-[#4a4a4a]"> · {cve}</span>
                        </p>
                        <p className="text-[11px] text-[#5a5a5a] truncate mt-0.5">{f.summary}</p>
                        {f.fixedVersion && <p className="text-[11px] text-[#16a34a] mt-0.5">Fixed in {f.fixedVersion} — upgrade to resolve</p>}
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
          </>
        )}
        {suppressions.length > 0 && (
          <>
          <SectionLabel text="Ignored Findings" />
          <div className="rounded-xl border border-[#1e1e1e] bg-[#0f0f0f] overflow-hidden">
            <button onClick={handleToggleIgnored} className="w-full px-4 py-3 flex items-center gap-2.5 hover:bg-[#131313] transition-colors">
              <span className="text-[#3a3a3a]"><IconX /></span>
              <span className="text-[12px] font-semibold text-[#8a8a8a] flex-1 text-left">{suppressions.length} marked as false positive</span>
              <span className="text-[11px] font-mono text-[#5a5a5a] tabular-nums">{ignoredOpen ? 'Hide' : 'Show'}</span>
              <span className={`text-[#3a3a3a] transition-transform ${ignoredOpen ? 'rotate-180' : ''}`}><IconChevronDown /></span>
            </button>
            {ignoredOpen && (
              <div className="border-t border-[#181818] divide-y divide-[#141414] max-h-[240px] overflow-y-auto">
                {suppressions.map(s => (
                  <div key={s.key} className="px-4 py-2.5 flex items-center gap-3">
                    <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ backgroundColor: SEVERITY_CONFIG[s.severity]?.color ?? '#6b7280' }} />
                    <div className="flex-1 min-w-0">
                      <p className="text-[12px] text-[#8a8a8a] truncate">{s.title}</p>
                      {s.file && <p className="text-[10px] font-mono text-[#3a3a3a] truncate">{s.file}</p>}
                    </div>
                    <button onClick={() => handleRestoreSuppression(s.key)} className="shrink-0 px-2.5 py-1 rounded-md text-[11px] font-medium text-[#5a5a5a] hover:text-[#eeeeee] border border-[#222222] hover:border-[#333333] transition-all">Restore</button>
                  </div>
                ))}
              </div>
            )}
          </div>
          </>
        )}
        {result.analysis?.suppressedCount ? (
          <p className="text-[11px] text-[#3a3a3a] text-center">{result.analysis.suppressedCount} previously ignored finding{result.analysis.suppressedCount !== 1 ? 's were' : ' was'} excluded from this scan&apos;s score</p>
        ) : null}
        {result.analysisError && <div className="rounded-xl border border-[#2a1a0a] bg-[#150d00] p-4"><p className="text-[10px] text-[#6b4020] uppercase tracking-widest font-semibold mb-1">AI analysis failed</p><p className="text-[12px] font-mono text-[#c8905a]">{result.analysisError}</p></div>}
        {!result.analysis && !result.analysisError && <div className="rounded-xl border border-[#1e1e1e] bg-[#0f0f0f] p-4 flex items-start gap-3"><span className="text-[#3a3a3a] shrink-0 mt-0.5"><IconKey /></span><div><p className="text-[12px] font-medium text-[#5a5a5a]">AI analysis not available</p><p className="text-[11px] text-[#3a3a3a] mt-0.5">Add an Anthropic API key in Settings to enable AI-powered analysis.</p></div></div>}
        {result.error && <div className="rounded-xl border border-[#2a1515] bg-[#150a0a] p-4"><p className="text-[10px] text-[#6b2a2a] uppercase tracking-widest font-semibold mb-2">Scanner errors</p><pre className="text-[11px] font-mono text-[#c87171] whitespace-pre-wrap leading-relaxed">{result.error}</pre></div>}
        {!totalFindings && !result.error && !result.analysis && <div className="rounded-xl border border-[#1e1e1e] bg-[#0f0f0f] p-6 text-center"><p className="text-[13px] font-medium text-[#16a34a]">Clean scan</p><p className="text-[12px] text-[#3a3a3a] mt-1">No vulnerabilities, secrets, or vulnerable dependencies were detected.</p></div>}
        <div className="h-1" />
      </div>
      <div className="shrink-0 px-6 pb-5 pt-3 border-t border-[#181818] bg-[#0a0a0a] space-y-2">
        {result.analysis && (
          <div className="flex gap-2">
            <button onClick={handleExportPdf} disabled={exporting} className="flex-1 py-2.5 rounded-xl text-[12px] font-semibold text-[#eeeeee] bg-[#1a1a1a] hover:bg-[#222222] border border-[#252525] hover:border-[#333333] disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-1.5">
              {exporting ? <div className="w-3 h-3 rounded-full border border-[#4a4a4a] border-t-[#eeeeee] animate-spin" /> : <IconDownload />}
              {exporting ? 'Exporting…' : 'Export PDF'}
            </button>
            <button onClick={handleCopySummary} disabled={copying} className="flex-1 py-2.5 rounded-xl text-[12px] font-semibold text-[#eeeeee] bg-[#1a1a1a] hover:bg-[#222222] border border-[#252525] hover:border-[#333333] disabled:opacity-40 transition-all flex items-center justify-center gap-1.5">
              {copying ? <IconCheck /> : <IconCopy />}
              {copying ? 'Copied!' : 'Copy summary'}
            </button>
          </div>
        )}
        <div className="flex gap-3">
          <button onClick={onBack} className="flex-1 py-3 rounded-xl text-[13px] font-semibold text-[#8b8b8b] hover:text-[#eeeeee] border border-[#222222] hover:border-[#333333] bg-transparent hover:bg-[#111111] transition-all">Back to folder</button>
          <button onClick={onNewScan} className="flex-1 py-3 rounded-xl text-[13px] font-semibold text-white bg-[#5e6ad2] hover:bg-[#6b77df] transition-colors">New scan</button>
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Folder ready view
// ---------------------------------------------------------------------------

function FolderReadyView({ path, stats, onReset, onStartScan, hasApiKey, onShowInfo }: {
  path: string; stats: FolderStats; onReset: () => void; onStartScan: () => void; hasApiKey: boolean; onShowInfo: () => void
}): React.ReactElement {
  const folderName = path.replace(/\\/g, '/').split('/').filter(Boolean).pop() ?? path
  const formattedSize = stats.totalSizeMB >= 1000 ? `${(stats.totalSizeMB / 1024).toFixed(1)} GB` : `${stats.totalSizeMB} MB`
  const formattedCount = stats.fileCount >= 1000 ? `${(stats.fileCount / 1000).toFixed(1)}k` : String(stats.fileCount)
  const [hookStatus, setHookStatus] = useState<'unknown' | 'installed' | 'absent'>('unknown')
  const [hookBusy, setHookBusy] = useState(false)
  const [hookError, setHookError] = useState<string | null>(null)

  useEffect(() => {
    window.api.getHookStatus(path)
      .then(installed => setHookStatus(installed ? 'installed' : 'absent'))
      .catch(() => setHookStatus('unknown'))
  }, [path])

  const handleToggleHook = useCallback(async (): Promise<void> => {
    if (hookBusy) return
    setHookBusy(true); setHookError(null)
    try {
      if (hookStatus === 'installed') {
        await window.api.uninstallHook(path)
        setHookStatus('absent')
      } else {
        await window.api.installHook(path, 60)
        setHookStatus('installed')
      }
    } catch (err) {
      setHookError(String(err).replace(/Error invoking remote method '[^']+': /, '').replace(/^Error: /, ''))
    } finally { setHookBusy(false) }
  }, [hookBusy, hookStatus, path])
  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      <div className="flex-1 overflow-y-auto px-6 py-5 space-y-3">
        <div className="rounded-xl border border-[#1e1e1e] bg-[#0f0f0f] p-4">
          <div className="flex items-start gap-3">
            <div className="w-9 h-9 rounded-lg bg-[#161616] border border-[#252525] flex items-center justify-center text-[#5e6ad2] shrink-0 mt-0.5"><IconFolder size={16} /></div>
            <div className="flex-1 min-w-0"><p className="text-[14px] font-semibold text-[#f0f0f0] tracking-tight truncate">{folderName}</p><p className="text-[11px] font-mono text-[#3a3a3a] truncate mt-0.5" title={path}>{path}</p></div>
            <button onClick={onReset} className="shrink-0 px-2.5 py-1.5 rounded-lg text-[12px] font-medium text-[#5a5a5a] hover:text-[#c4c4c4] hover:bg-[#1a1a1a] border border-transparent hover:border-[#252525] transition-all">Change</button>
          </div>
        </div>
        <div className="grid grid-cols-3 gap-3">
          <StatPill label="Files" value={formattedCount} /><StatPill label="Total size" value={formattedSize} /><StatPill label="Languages" value={String(stats.languages.length)} />
        </div>
        {stats.languages.length > 0 && (
          <div className="rounded-xl border border-[#1e1e1e] bg-[#0f0f0f] p-4">
            <p className="text-[10px] text-[#3a3a3a] uppercase tracking-widest font-semibold mb-3">Detected Languages</p>
            <div className="flex flex-wrap gap-2">{stats.languages.map(lang => <div key={lang} className="flex items-center gap-1.5 px-2.5 py-[5px] rounded-full bg-[#141414] border border-[#222222]"><span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ backgroundColor: getLangColor(lang) }} /><span className="text-[12px] font-medium text-[#b4b4b4]">{lang}</span></div>)}</div>
          </div>
        )}
        <div className="rounded-xl border border-[#1e1e1e] bg-[#0f0f0f] overflow-hidden">
          <div className="px-4 py-2.5 border-b border-[#181818] flex items-center justify-between"><p className="text-[10px] text-[#3a3a3a] uppercase tracking-widest font-semibold">File Preview</p><span className="text-[10px] font-mono text-[#2a2a2a]">2 levels deep</span></div>
          <div className="max-h-[240px] overflow-y-auto px-2 py-2">{stats.tree.length === 0 ? <p className="text-[12px] font-mono text-[#3a3a3a] px-3 py-2">No files found</p> : stats.tree.map((node, i) => <FileTreeEntry key={i} node={node} depth={0} />)}</div>
        </div>
        {hookStatus !== 'unknown' && (
          <div className="rounded-xl border border-[#1e1e1e] bg-[#0f0f0f] px-4 py-3">
            <div className="flex items-center gap-2.5">
              <span className={hookStatus === 'installed' ? 'text-[#16a34a]' : 'text-[#3a3a3a]'}><IconShield /></span>
              <div className="flex-1 min-w-0">
                <p className="text-[12px] font-medium text-[#c4c4c4]">Pre-commit guard</p>
                <p className="text-[11px] text-[#4a4a4a] mt-0.5">{hookStatus === 'installed' ? 'Commits are blocked when the security score drops below 60' : 'Block commits in this repo when the security score drops below 60'}</p>
              </div>
              <button onClick={handleToggleHook} disabled={hookBusy} className={`shrink-0 px-3 py-1.5 rounded-lg text-[12px] font-semibold transition-all disabled:opacity-40 ${hookStatus === 'installed' ? 'text-[#5a5a5a] hover:text-[#ef4444] border border-[#222222] hover:border-[#3a1a1a]' : 'text-[#16a34a] bg-[#166534]/10 hover:bg-[#166534]/20 border border-[#166534]/30'}`}>
                {hookBusy ? '…' : hookStatus === 'installed' ? 'Remove' : 'Install'}
              </button>
            </div>
            {hookError && <p className="text-[11px] text-[#f87171] mt-2">{hookError}</p>}
          </div>
        )}
        {!hasApiKey && <div className="rounded-xl border border-[#222222] bg-[#0f0f0f] px-4 py-3 flex items-center gap-2.5"><span className="text-[#3a3a3a] shrink-0"><IconKey /></span><p className="text-[12px] text-[#4a4a4a] flex-1">No API key — AI analysis will be skipped.</p></div>}
        <div className="h-1" />
      </div>
      <div className="shrink-0 px-6 pb-5 pt-3 border-t border-[#181818] bg-[#0a0a0a] space-y-2.5">
        <button onClick={onStartScan} className="w-full py-4 rounded-xl text-white text-[14px] font-semibold tracking-tight flex items-center justify-center gap-2.5 bg-[#16a34a] hover:bg-[#15803d] transition-colors active:scale-[0.99]" style={{ boxShadow: '0 0 40px rgba(22,163,74,0.2), 0 1px 3px rgba(0,0,0,0.5)' }}>
          <IconPlay />Start Scan
        </button>
        <button onClick={onShowInfo} className="mx-auto flex items-center gap-1.5 text-[11px] font-medium text-[#2a2a2a] hover:text-[#5a5a5a] transition-colors">
          <IconInfo />What we scan for
        </button>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Drop zone
// ---------------------------------------------------------------------------

function DropZone({ isDragging, onDragOver, onDragLeave, onDrop, onBrowse, onShowInfo }: {
  isDragging: boolean; onDragOver: (e: React.DragEvent) => void; onDragLeave: (e: React.DragEvent) => void; onDrop: (e: React.DragEvent) => void; onBrowse: () => void; onShowInfo: () => void
}): React.ReactElement {
  return (
    <div className="flex-1 flex items-center justify-center p-8">
      <div className="w-full max-w-lg space-y-4">
        <div onDragOver={onDragOver} onDragLeave={onDragLeave} onDrop={onDrop} className={`rounded-2xl border-2 border-dashed px-12 py-14 flex flex-col items-center gap-5 text-center transition-all duration-150 cursor-default ${isDragging ? 'border-[#5e6ad2] bg-[#5e6ad2]/5 scale-[1.01]' : 'border-[#222222] hover:border-[#333333] hover:bg-[#0e0e0e]'}`}>
          <div className={`w-14 h-14 rounded-2xl flex items-center justify-center transition-all duration-150 ${isDragging ? 'bg-[#5e6ad2]/15 text-[#5e6ad2]' : 'bg-[#161616] text-[#333333]'}`}><IconFolder size={26} /></div>
          <div className="space-y-2">
            <p className="text-[15px] font-semibold text-[#eeeeee] tracking-tight">{isDragging ? 'Release to select folder' : 'Drop your project folder here'}</p>
            <p className="text-[13px] text-[#4a4a4a] leading-relaxed">Snagify scans for secrets, vulnerabilities, and<br />vulnerable dependencies using Semgrep, Gitleaks, and OSV</p>
          </div>
          <div className="flex items-center gap-3 w-[140px]"><div className="h-px flex-1 bg-[#1e1e1e]" /><span className="text-[10px] text-[#333333] uppercase tracking-widest font-semibold">or</span><div className="h-px flex-1 bg-[#1e1e1e]" /></div>
          <button onClick={onBrowse} className="px-5 py-2.5 rounded-lg text-[13px] font-semibold bg-[#5e6ad2] hover:bg-[#6b77df] text-white transition-colors active:scale-[0.97]">Browse folder</button>
        </div>
        <button onClick={onShowInfo} className="mx-auto flex items-center gap-1.5 text-[11px] font-medium text-[#2a2a2a] hover:text-[#5a5a5a] transition-colors">
          <IconInfo />What we scan for
        </button>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// New scan view
// ---------------------------------------------------------------------------

function NewScanView({ hasApiKey, onScanningChange }: { hasApiKey: boolean; onScanningChange?: (scanning: boolean) => void }): React.ReactElement {
  const [isDragging, setIsDragging] = useState(false)
  const [folderPath, setFolderPath] = useState<string | null>(null)
  const [stats, setStats] = useState<FolderStats | null>(null)
  const [phase, setPhase] = useState<ScanPhase>('idle')
  const [scanProgress, setScanProgress] = useState<ScanProgress | null>(null)
  const [scanResult, setScanResult] = useState<ScanResult | null>(null)
  const [isCancelling, setIsCancelling] = useState(false)

  // Notify parent when scanning starts or stops
  useEffect(() => {
    onScanningChange?.(phase === 'scanning')
  }, [phase, onScanningChange])
  const [showInfo, setShowInfo] = useState(false)
  const progressCleanupRef = useRef<(() => void) | null>(null)

  useEffect(() => {
    const prevent = (e: DragEvent): void => { e.preventDefault(); e.stopPropagation() }
    document.addEventListener('dragover', prevent); document.addEventListener('drop', prevent)
    return () => { document.removeEventListener('dragover', prevent); document.removeEventListener('drop', prevent) }
  }, [])
  useEffect(() => () => { progressCleanupRef.current?.() }, [])

  const loadFolder = useCallback(async (path: string): Promise<void> => {
    setFolderPath(path); setPhase('loading'); setStats(null)
    try { const result = await window.api.getFolderStats(path); setStats(result); setPhase('ready') }
    catch (err) { console.error('getFolderStats failed:', err); setFolderPath(null); setPhase('idle') }
  }, [])

  const handleBrowse = useCallback(async (): Promise<void> => { const path = await window.api.selectFolder(); if (path) await loadFolder(path) }, [loadFolder])
  const handleDragOver = useCallback((e: React.DragEvent): void => { e.preventDefault(); setIsDragging(true) }, [])
  const handleDragLeave = useCallback((e: React.DragEvent): void => { e.preventDefault(); setIsDragging(false) }, [])
  const handleDrop = useCallback(async (e: React.DragEvent): Promise<void> => {
    e.preventDefault(); e.stopPropagation(); setIsDragging(false)
    const files = Array.from(e.dataTransfer.files)
    if (files.length > 0) { const fp = (files[0] as File & { path: string }).path; if (fp) await loadFolder(fp) }
  }, [loadFolder])
  const handleReset = useCallback((): void => {
    progressCleanupRef.current?.(); progressCleanupRef.current = null
    setFolderPath(null); setStats(null); setPhase('idle'); setScanProgress(null); setScanResult(null); setIsCancelling(false)
  }, [])
  const handleStartScan = useCallback(async (): Promise<void> => {
    if (!folderPath) return
    setScanProgress(null); setScanResult(null); setIsCancelling(false); setPhase('scanning')
    progressCleanupRef.current?.()
    progressCleanupRef.current = window.api.onScanProgress(p => setScanProgress(p))
    try {
      const result = await window.api.runScan(folderPath)
      progressCleanupRef.current?.(); progressCleanupRef.current = null
      if (result.cancelled) { setIsCancelling(false); setPhase('ready') }
      else { setScanResult(result); setPhase('done') }
    } catch (err) {
      progressCleanupRef.current?.(); progressCleanupRef.current = null
      setScanResult({ semgrepFindings: [], gitleaksFindings: [], osvFindings: [], error: String(err) }); setPhase('done')
    }
  }, [folderPath])
  const handleCancelScan = useCallback((): void => { if (isCancelling) return; setIsCancelling(true); window.api.cancelScan() }, [isCancelling])

  if (phase === 'loading' && folderPath) return <LoadingView path={folderPath} />
  if (phase === 'scanning' && folderPath) return <ScanningView folderPath={folderPath} progress={scanProgress} isCancelling={isCancelling} onCancel={handleCancelScan} />
  if (phase === 'done' && scanResult && folderPath) return <ScanResultView result={scanResult} folderPath={folderPath} onBack={() => setPhase('ready')} onNewScan={handleReset} />
  if (phase === 'ready' && folderPath && stats) return (
    <>
      {showInfo && <ScanInfoModal onClose={() => setShowInfo(false)} />}
      <FolderReadyView path={folderPath} stats={stats} onReset={handleReset} onStartScan={handleStartScan} hasApiKey={hasApiKey} onShowInfo={() => setShowInfo(true)} />
    </>
  )
  return (
    <>
      {showInfo && <ScanInfoModal onClose={() => setShowInfo(false)} />}
      <DropZone isDragging={isDragging} onDragOver={handleDragOver} onDragLeave={handleDragLeave} onDrop={handleDrop} onBrowse={handleBrowse} onShowInfo={() => setShowInfo(true)} />
    </>
  )
}

// ---------------------------------------------------------------------------
// Settings view
// ---------------------------------------------------------------------------

function SettingsView({ licenseStatus, onApiKeyChange, onDeactivate }: {
  licenseStatus: LicenseStatus; onApiKeyChange: (hasKey: boolean) => void; onDeactivate: () => void
}): React.ReactElement {
  const [keyInput, setKeyInput] = useState('')
  const [savingKey, setSavingKey] = useState(false)
  const [keySaved, setKeySaved] = useState(false)
  const [keyError, setKeyError] = useState<string | null>(null)
  const [hasApiKey, setHasApiKey] = useState(false)
  const [deactivating, setDeactivating] = useState(false)
  const [confirmDeactivate, setConfirmDeactivate] = useState(false)
  const [appVersion, setAppVersion] = useState<string>('')
  const [branding, setBranding] = useState<ReportBranding>(() => loadBranding())
  const [logoError, setLogoError] = useState<string | null>(null)
  const [aiInfo, setAiInfo] = useState<AiProviderInfo | null>(null)
  const [modelInput, setModelInput] = useState('')
  const [baseUrlInput, setBaseUrlInput] = useState('')
  const [testingProvider, setTestingProvider] = useState(false)
  const [testResult, setTestResult] = useState<{ ok: boolean; detail: string } | null>(null)

  const refreshProvider = useCallback(async (): Promise<void> => {
    try {
      const info = await window.api.getAiProvider()
      setAiInfo(info)
      setModelInput(info.model)
      setBaseUrlInput(info.baseUrl)
    } catch { /* leave as-is */ }
  }, [])

  useEffect(() => { void refreshProvider() }, [refreshProvider])

  const handleProviderChange = useCallback(async (provider: string): Promise<void> => {
    const spec = aiInfo?.providers.find(p => p.id === provider)
    setTestResult(null)
    await window.api.setAiProvider({ provider, model: spec?.defaultModel })
    await refreshProvider()
  }, [aiInfo, refreshProvider])

  const handleSaveProviderMeta = useCallback(async (): Promise<void> => {
    if (!aiInfo) return
    await window.api.setAiProvider({ provider: aiInfo.provider, model: modelInput.trim(), baseUrl: baseUrlInput.trim() })
    await refreshProvider()
  }, [aiInfo, modelInput, baseUrlInput, refreshProvider])

  const handleTestProvider = useCallback(async (): Promise<void> => {
    setTestingProvider(true); setTestResult(null)
    try { setTestResult(await window.api.testAiProvider()) }
    catch (e) { setTestResult({ ok: false, detail: String(e) }) }
    finally { setTestingProvider(false) }
  }, [])

  const updateBranding = useCallback((patch: Partial<ReportBranding>): void => {
    setBranding(prev => {
      const next = { ...prev, ...patch }
      saveBranding(next)
      return next
    })
  }, [])

  const handleLogoUpload = useCallback((e: React.ChangeEvent<HTMLInputElement>): void => {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    setLogoError(null)
    if (file.size > 500_000) { setLogoError('Logo must be under 500 KB'); return }
    const reader = new FileReader()
    reader.onload = () => {
      const dataUrl = String(reader.result ?? '')
      const img = new Image()
      img.onload = () => updateBranding({ logoDataUrl: dataUrl, logoW: img.naturalWidth, logoH: img.naturalHeight })
      img.onerror = () => setLogoError('Could not read that image')
      img.src = dataUrl
    }
    reader.onerror = () => setLogoError('Could not read that file')
    reader.readAsDataURL(file)
  }, [updateBranding])

  useEffect(() => {
    window.api.getApiKeyStatus().then(s => setHasApiKey(s))
    window.api.getAppVersion().then(v => setAppVersion(v)).catch(() => {})
  }, [])

  const handleSaveKey = useCallback(async (): Promise<void> => {
    const trimmed = keyInput.trim(); if (!trimmed) return
    setSavingKey(true); setKeyError(null)
    try { await window.api.saveApiKey(trimmed); setHasApiKey(true); setKeyInput(''); setKeySaved(true); onApiKeyChange(true); setTimeout(() => setKeySaved(false), 2500) }
    catch (err) { setKeyError(String(err)) }
    finally { setSavingKey(false) }
  }, [keyInput, onApiKeyChange])

  const handleDeactivate = useCallback(async (): Promise<void> => {
    setDeactivating(true)
    try { await window.api.deactivateLicense(); onDeactivate() }
    finally { setDeactivating(false); setConfirmDeactivate(false) }
  }, [onDeactivate])

  return (
    <div className="flex-1 overflow-y-auto px-6 py-6 space-y-5">
      {/* License */}
      <div className="rounded-xl border border-[#1e1e1e] bg-[#0f0f0f] overflow-hidden">
        <div className="px-5 py-4 border-b border-[#1a1a1a] flex items-center gap-3">
          <span className="text-[#5e6ad2]"><svg width="16" height="16" viewBox="0 0 24 24" fill="none"><rect x="3" y="11" width="18" height="11" rx="2" stroke="currentColor" strokeWidth="1.5" /><path d="M7 11V7a5 5 0 0110 0v4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" /></svg></span>
          <div><p className="text-[13px] font-semibold text-[#eeeeee]">License</p><p className="text-[11px] text-[#3a3a3a] mt-0.5">Snagify license activation</p></div>
          <div className="ml-auto"><span className="flex items-center gap-1.5 text-[11px] font-medium text-[#16a34a]"><span className="w-1.5 h-1.5 rounded-full bg-[#16a34a]" />Active</span></div>
        </div>
        <div className="px-5 py-4 space-y-3">
          <div className="space-y-2">
            {licenseStatus.keyMasked && <div className="flex items-center justify-between"><span className="text-[12px] text-[#4a4a4a]">License key</span><span className="text-[12px] font-mono text-[#8a8a8a]">{licenseStatus.keyMasked}</span></div>}
            {licenseStatus.email && <div className="flex items-center justify-between"><span className="text-[12px] text-[#4a4a4a]">Account email</span><span className="text-[12px] font-mono text-[#8a8a8a]">{licenseStatus.email}</span></div>}
          </div>
          {!confirmDeactivate ? (
            <button onClick={() => setConfirmDeactivate(true)} className="text-[12px] font-medium text-[#5a5a5a] hover:text-[#ef4444] transition-colors">Deactivate license…</button>
          ) : (
            <div className="flex items-center gap-3 pt-1">
              <p className="text-[12px] text-[#8a8a8a] flex-1">Deactivate on this machine?</p>
              <button onClick={() => setConfirmDeactivate(false)} className="px-3 py-1.5 rounded-lg text-[12px] font-medium text-[#5a5a5a] border border-[#222222] hover:border-[#333333] transition-all">Cancel</button>
              <button onClick={handleDeactivate} disabled={deactivating} className="px-3 py-1.5 rounded-lg text-[12px] font-semibold text-white bg-[#ef4444] hover:bg-[#dc2626] disabled:opacity-40 transition-colors">{deactivating ? 'Deactivating…' : 'Deactivate'}</button>
            </div>
          )}
        </div>
      </div>

      {/* AI provider */}
      <div className="rounded-xl border border-[#1e1e1e] bg-[#0f0f0f] overflow-hidden">
        <div className="px-5 py-4 border-b border-[#1a1a1a] flex items-center gap-3">
          <span className="text-[#5e6ad2]"><IconKey /></span>
          <div><p className="text-[13px] font-semibold text-[#eeeeee]">AI Provider</p><p className="text-[11px] text-[#3a3a3a] mt-0.5">Powers analysis, fixes, and scalability review</p></div>
          <div className="ml-auto">{aiInfo?.configured
            ? <span className="flex items-center gap-1.5 text-[11px] font-medium text-[#16a34a]"><span className="w-1.5 h-1.5 rounded-full bg-[#16a34a]" />Configured</span>
            : <span className="flex items-center gap-1.5 text-[11px] font-medium text-[#5a5a5a]"><span className="w-1.5 h-1.5 rounded-full bg-[#333333]" />Not set</span>}</div>
        </div>
        <div className="px-5 py-4 space-y-3">
          {/* Provider picker */}
          <div className="grid grid-cols-1 gap-1.5">
            {(aiInfo?.providers ?? []).map(p => (
              <button
                key={p.id}
                onClick={() => handleProviderChange(p.id)}
                className={`w-full text-left px-3 py-2.5 rounded-lg border transition-all ${aiInfo?.provider === p.id ? 'border-[#5e6ad2] bg-[#5e6ad2]/10' : 'border-[#222222] bg-[#0a0a0a] hover:border-[#333333]'}`}
              >
                <div className="flex items-center gap-2">
                  <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${aiInfo?.provider === p.id ? 'bg-[#5e6ad2]' : 'bg-[#2a2a2a]'}`} />
                  <span className="text-[12px] font-medium text-[#d4d4d4] flex-1">{p.label}</span>
                  {!p.needsKey && <span className="text-[10px] text-[#16a34a] font-medium">no key needed</span>}
                </div>
              </button>
            ))}
          </div>

          {/* Base URL for OpenAI-compatible endpoints */}
          {aiInfo?.provider === 'openai-compatible' && (
            <input
              type="text" value={baseUrlInput} onChange={e => setBaseUrlInput(e.target.value)}
              onBlur={() => handleSaveProviderMeta()}
              placeholder="Base URL — e.g. https://api.groq.com/openai/v1"
              className="w-full px-3 py-2.5 rounded-lg text-[13px] font-mono bg-[#0a0a0a] border border-[#222222] text-[#eeeeee] placeholder-[#333333] focus:outline-none focus:border-[#5e6ad2] transition-colors"
              style={{ WebkitUserSelect: 'text', userSelect: 'text' } as React.CSSProperties}
            />
          )}

          {/* Model */}
          <div className="flex gap-2">
            <input
              type="text" value={modelInput} onChange={e => setModelInput(e.target.value)}
              onBlur={() => handleSaveProviderMeta()}
              placeholder={aiInfo?.model ?? 'model'}
              className="flex-1 px-3 py-2.5 rounded-lg text-[13px] font-mono bg-[#0a0a0a] border border-[#222222] text-[#eeeeee] placeholder-[#333333] focus:outline-none focus:border-[#5e6ad2] transition-colors"
              style={{ WebkitUserSelect: 'text', userSelect: 'text' } as React.CSSProperties}
              spellCheck={false}
            />
            <button onClick={handleTestProvider} disabled={testingProvider} className="px-4 py-2.5 rounded-lg text-[13px] font-semibold text-[#eeeeee] bg-[#1a1a1a] hover:bg-[#222222] border border-[#252525] disabled:opacity-40 transition-all">
              {testingProvider ? 'Testing…' : 'Test'}
            </button>
          </div>
          {testResult && (
            <p className={`text-[12px] ${testResult.ok ? 'text-[#16a34a]' : 'text-[#f87171]'}`}>
              {testResult.ok ? '✓ Provider reachable and responding' : testResult.detail}
            </p>
          )}

          {/* API key — hidden for providers that need none (e.g. Ollama) */}
          {aiInfo?.needsKey !== false && (
            <>
              <div className="flex gap-2">
                <input type="password" value={keyInput} onChange={e => setKeyInput(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleSaveKey()} placeholder={hasApiKey ? 'Enter new key to replace…' : 'API key'} className="flex-1 px-3 py-2.5 rounded-lg text-[13px] font-mono bg-[#0a0a0a] border border-[#222222] text-[#eeeeee] placeholder-[#333333] focus:outline-none focus:border-[#5e6ad2] transition-colors select-text" style={{ WebkitUserSelect: 'text', userSelect: 'text' } as React.CSSProperties} spellCheck={false} autoComplete="off" />
                <button onClick={handleSaveKey} disabled={savingKey || !keyInput.trim()} className="px-4 py-2.5 rounded-lg text-[13px] font-semibold bg-[#5e6ad2] hover:bg-[#6b77df] text-white disabled:opacity-40 disabled:cursor-not-allowed transition-colors flex items-center gap-2">
                  {savingKey ? <div className="w-3 h-3 rounded-full border border-white/40 border-t-white animate-spin" /> : keySaved ? <><IconCheck />Saved</> : 'Save'}
                </button>
              </div>
              {keyError && <p className="text-[12px] font-mono text-[#f87171]">{keyError}</p>}
              <div className="flex items-center gap-2 text-[11px] text-[#3a3a3a]"><span className="shrink-0"><IconLock /></span><span>Stored encrypted using the OS keychain via Electron safeStorage.</span></div>
            </>
          )}
          {aiInfo?.needsKey === false && (
            <div className="flex items-center gap-2 text-[11px] text-[#16a34a]"><span className="shrink-0"><IconLock /></span><span>Runs locally — your code never leaves this machine.</span></div>
          )}
        </div>
      </div>

      {/* Report branding */}
      <div className="rounded-xl border border-[#1e1e1e] bg-[#0f0f0f] overflow-hidden">
        <div className="px-5 py-4 border-b border-[#1a1a1a] flex items-center gap-3">
          <span className="text-[#5e6ad2]"><IconFile /></span>
          <div><p className="text-[13px] font-semibold text-[#eeeeee]">Report branding</p><p className="text-[11px] text-[#3a3a3a] mt-0.5">White-label PDF reports with your company name and logo</p></div>
          <div className="ml-auto">{branding.company || branding.logoDataUrl ? <span className="flex items-center gap-1.5 text-[11px] font-medium text-[#16a34a]"><span className="w-1.5 h-1.5 rounded-full bg-[#16a34a]" />Active</span> : <span className="flex items-center gap-1.5 text-[11px] font-medium text-[#5a5a5a]"><span className="w-1.5 h-1.5 rounded-full bg-[#333333]" />Default</span>}</div>
        </div>
        <div className="px-5 py-4 space-y-3">
          <div className="grid grid-cols-2 gap-2">
            <input
              type="text" value={branding.company}
              onChange={e => updateBranding({ company: e.target.value })}
              placeholder="Your company name"
              className="px-3 py-2.5 rounded-lg text-[13px] bg-[#0a0a0a] border border-[#222222] text-[#eeeeee] placeholder-[#333333] focus:outline-none focus:border-[#5e6ad2] transition-colors"
              style={{ WebkitUserSelect: 'text', userSelect: 'text' } as React.CSSProperties}
            />
            <input
              type="text" value={branding.client}
              onChange={e => updateBranding({ client: e.target.value })}
              placeholder="Client name (optional)"
              className="px-3 py-2.5 rounded-lg text-[13px] bg-[#0a0a0a] border border-[#222222] text-[#eeeeee] placeholder-[#333333] focus:outline-none focus:border-[#5e6ad2] transition-colors"
              style={{ WebkitUserSelect: 'text', userSelect: 'text' } as React.CSSProperties}
            />
          </div>
          <div className="flex items-center gap-3">
            {branding.logoDataUrl ? (
              <>
                <img src={branding.logoDataUrl} alt="Logo" className="h-8 max-w-[120px] object-contain rounded bg-[#141414] border border-[#222222] px-2 py-1" />
                <button onClick={() => updateBranding({ logoDataUrl: '', logoW: 0, logoH: 0 })} className="text-[12px] font-medium text-[#5a5a5a] hover:text-[#ef4444] transition-colors">Remove logo</button>
              </>
            ) : (
              <label className="px-3 py-2 rounded-lg text-[12px] font-medium text-[#8a8a8a] hover:text-[#eeeeee] bg-[#141414] hover:bg-[#1a1a1a] border border-[#222222] hover:border-[#333333] cursor-pointer transition-all">
                Upload logo (PNG/JPEG)
                <input type="file" accept="image/png,image/jpeg" className="hidden" onChange={handleLogoUpload} />
              </label>
            )}
            {logoError && <p className="text-[11px] text-[#f87171]">{logoError}</p>}
          </div>
          <p className="text-[11px] text-[#3a3a3a]">When set, exported PDFs show your logo and &ldquo;Prepared by {branding.company || 'your company'}{branding.client ? ` for ${branding.client}` : ''}&rdquo; instead of Snagify branding.</p>
        </div>
      </div>

      {/* Model info */}
      <div className="rounded-xl border border-[#1e1e1e] bg-[#0f0f0f] px-5 py-4 space-y-3">
        <p className="text-[10px] text-[#3a3a3a] uppercase tracking-widest font-semibold">Model configuration</p>
        <div className="space-y-2">
          {[
            { label: 'Provider', value: aiInfo?.providers.find(p => p.id === aiInfo?.provider)?.label ?? '—' },
            { label: 'Model', value: aiInfo?.model ?? '—' },
            { label: 'Analysis', value: 'Semgrep + Gitleaks + OSV findings' }
          ].map(({ label, value }) => (
            <div key={label} className="flex items-center justify-between"><span className="text-[12px] text-[#4a4a4a]">{label}</span><span className="text-[12px] font-mono text-[#8a8a8a]">{value}</span></div>
          ))}
        </div>
      </div>

      {/* About */}
      <div className="rounded-xl border border-[#1e1e1e] bg-[#0f0f0f] px-5 py-4 space-y-2">
        <p className="text-[10px] text-[#3a3a3a] uppercase tracking-widest font-semibold">About</p>
        <div className="flex items-center justify-between">
          <span className="text-[12px] text-[#4a4a4a]">Version</span>
          <span className="text-[12px] font-mono text-[#8a8a8a]">{appVersion ? `v${appVersion}` : '—'}</span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-[12px] text-[#4a4a4a]">Website</span>
          <span className="text-[12px] font-mono text-[#8a8a8a]">snagify.ca</span>
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// App shell
// ---------------------------------------------------------------------------

const navItems: NavEntry[] = [
  { id: 'dashboard', label: 'Dashboard', icon: <IconGrid /> },
  { id: 'new-scan',  label: 'New Scan',  icon: <IconScan /> },
  { id: 'history',   label: 'History',   icon: <IconHistory /> },
  { id: 'settings',  label: 'Settings',  icon: <IconSettings /> }
]
const pageTitles: Record<NavItem, string> = { dashboard: 'Dashboard', 'new-scan': 'New Scan', history: 'History', settings: 'Settings' }

function AppShell({ licenseStatus, onDeactivate }: { licenseStatus: LicenseStatus; onDeactivate: () => void }): React.ReactElement {
  const [activeNav, setActiveNav] = useState<NavItem>('dashboard')
  const [displayNav, setDisplayNav] = useState<NavItem>('dashboard')
  const [fading, setFading] = useState(false)
  const [hasApiKey, setHasApiKey] = useState(false)
  const [isScanning, setIsScanning] = useState(false)
  const fadeTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => { window.api.getApiKeyStatus().then(setHasApiKey) }, [])

  const handleNavigate = useCallback((page: NavItem) => {
    // Block all navigation while a scan is running
    if (isScanning) return
    if (page === activeNav) return
    setFading(true)
    setActiveNav(page)
    if (fadeTimer.current) clearTimeout(fadeTimer.current)
    fadeTimer.current = setTimeout(() => {
      setDisplayNav(page)
      setFading(false)
    }, 75)
  }, [activeNav, isScanning])

  // Keyboard shortcuts
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent): void => {
      const mod = e.metaKey || e.ctrlKey
      if (!mod) return
      if (e.key === 'n' || e.key === 'N') { e.preventDefault(); handleNavigate('new-scan') }
      else if (e.key === 'h' || e.key === 'H') { e.preventDefault(); handleNavigate('history') }
      else if (e.key === ',') { e.preventDefault(); handleNavigate('settings') }
      else if (e.key === 'd' || e.key === 'D') { e.preventDefault(); handleNavigate('dashboard') }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [handleNavigate])

  // Menu-driven navigation from main process
  useEffect(() => {
    const unsub = window.api.onNavigateTo((page) => {
      const valid: NavItem[] = ['dashboard', 'new-scan', 'history', 'settings']
      if (valid.includes(page as NavItem)) handleNavigate(page as NavItem)
    })
    return unsub
  }, [handleNavigate])

  useEffect(() => () => { if (fadeTimer.current) clearTimeout(fadeTimer.current) }, [])

  return (
    <div className="flex h-screen overflow-hidden bg-[#0a0a0a] text-[#f5f5f5] font-sans select-none">
      <aside className="w-[220px] shrink-0 flex flex-col border-r border-[#181818] bg-[#0d0d0d]">
        <div className="h-12 flex items-center border-b border-[#181818] gap-2.5 pr-4" style={{ WebkitAppRegion: 'drag', paddingLeft: navigator.platform.toLowerCase().includes('mac') ? '80px' : '16px' } as React.CSSProperties}>
          <LogoMark size={20} />
          <span className="text-[13px] font-semibold tracking-tight text-[#eeeeee]">Snagify</span>
        </div>
        <nav className="flex-1 px-2 py-3 space-y-px overflow-y-auto">
          {navItems.map(item => {
            const active = activeNav === item.id
            const blocked = isScanning && item.id !== 'new-scan'
            return (
              <button key={item.id} onClick={() => handleNavigate(item.id)}
                disabled={blocked}
                title={blocked ? 'Scan in progress — navigation locked' : undefined}
                className={`w-full flex items-center gap-2.5 px-3 py-[7px] rounded-md text-[13px] font-medium transition-all duration-100 relative overflow-hidden
                  ${blocked ? 'opacity-30 cursor-not-allowed' : ''}
                  ${active ? 'bg-[#171717] text-[#eeeeee]' : !blocked ? 'text-[#5a5a5a] hover:text-[#c4c4c4] hover:bg-[#131313]' : 'text-[#5a5a5a]'}`}>
                {active && <span className="absolute left-0 top-[6px] bottom-[6px] w-[2px] rounded-r-full bg-[#5e6ad2]" />}
                <span className={`shrink-0 ${active ? 'text-[#5e6ad2]' : 'text-[#404040]'}`}>{item.icon}</span>
                <span className="flex-1 text-left">{item.label}</span>
                {item.id === 'new-scan' && isScanning && (
                  <span className="flex items-center gap-1 text-[10px] font-mono text-[#84f88e]">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#84f88e] animate-pulse" />
                    scanning
                  </span>
                )}
              </button>
            )
          })}
        </nav>
        <div className="px-3 py-3 border-t border-[#181818]">
          <div className="flex items-center gap-2.5 px-2 py-1.5 rounded-md hover:bg-[#131313] cursor-pointer transition-colors">
            <div className="w-6 h-6 rounded-full bg-gradient-to-br from-[#5e6ad2] to-[#8b5cf6] flex items-center justify-center text-[10px] font-bold text-white shrink-0">S</div>
            <div className="flex-1 min-w-0"><p className="text-[12px] font-medium text-[#b4b4b4] truncate">Snagify</p><p className="text-[10px] font-mono text-[#333333]">snagify.ca</p></div>
          </div>
        </div>
      </aside>

      <main className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <header className="h-12 shrink-0 flex items-center px-6 border-b border-[#181818]" style={{ WebkitAppRegion: 'drag' } as React.CSSProperties}>
          <div className="flex items-center" style={{ WebkitAppRegion: 'no-drag' } as React.CSSProperties}>
            <h1 className="text-[13px] font-medium text-[#eeeeee]">{pageTitles[activeNav]}</h1>
          </div>
        </header>
        <div className={`flex-1 flex flex-col overflow-hidden transition-opacity duration-75 ${fading ? 'opacity-0' : 'opacity-100'}`}>
          {displayNav === 'dashboard' && <DashboardView onNavigate={handleNavigate} />}
          {/* NewScanView stays mounted while scanning so the scan is never interrupted */}
          <div style={{ display: displayNav === 'new-scan' || isScanning ? 'flex' : 'none', flex: 1, flexDirection: 'column', overflow: 'hidden' }}>
            <NewScanView hasApiKey={hasApiKey} onScanningChange={setIsScanning} />
          </div>
          {displayNav === 'history'   && <HistoryView />}
          {displayNav === 'settings'  && <SettingsView licenseStatus={licenseStatus} onApiKeyChange={setHasApiKey} onDeactivate={onDeactivate} />}
        </div>
      </main>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Root — license gate
// ---------------------------------------------------------------------------

function AppInner(): React.ReactElement {
  const [appState, setAppState] = useState<AppState>('checking')
  const [licenseStatus, setLicenseStatus] = useState<LicenseStatus>({ activated: false, email: null, keyMasked: null })
  const [accountMode, setAccountMode] = useState(false)

  useEffect(() => {
    // Prefer account login when Supabase is configured; fall back to license keys
    window.api.authAvailable().then(async available => {
      if (available) {
        setAccountMode(true)
        try {
          const info = await window.api.authGetSession()
          if (info.signedIn && info.licensed) {
            setLicenseStatus({ activated: true, email: info.email, keyMasked: info.plan ? info.plan.toUpperCase() : 'ACCOUNT' })
            setAppState('licensed')
            return
          }
        } catch { /* fall through to login screen */ }
        setAppState('unlicensed')
        return
      }
      const status = await window.api.getLicenseStatus()
      setLicenseStatus(status)
      setAppState(status.activated ? 'licensed' : 'unlicensed')
    }).catch(() => setAppState('unlicensed'))
  }, [])

  if (appState === 'checking') {
    return (
      <div className="flex h-screen items-center justify-center bg-[#0a0a0a]">
        <div className="flex gap-1.5">{[0,1,2].map(i => <div key={i} className="w-1.5 h-1.5 rounded-full bg-[#252525] animate-pulse" style={{ animationDelay: `${i * 180}ms` }} />)}</div>
      </div>
    )
  }

  if (appState === 'unlicensed') {
    if (accountMode) {
      return (
        <AccountLoginScreen
          onLicensed={info => {
            setLicenseStatus({ activated: true, email: info.email, keyMasked: info.plan ? info.plan.toUpperCase() : 'ACCOUNT' })
            setAppState('licensed')
          }}
        />
      )
    }
    return (
      <LicenseActivationScreen
        onActivated={email => {
          setLicenseStatus({ activated: true, email, keyMasked: null })
          window.api.getLicenseStatus().then(setLicenseStatus)
          setAppState('licensed')
        }}
      />
    )
  }

  return (
    <AppShell
      licenseStatus={licenseStatus}
      onDeactivate={async () => {
        if (accountMode) await window.api.authSignOut()
        setLicenseStatus({ activated: false, email: null, keyMasked: null })
        setAppState('unlicensed')
      }}
    />
  )
}

export default function App(): React.ReactElement {
  return (
    <ErrorBoundary>
      <AppInner />
    </ErrorBoundary>
  )
}
