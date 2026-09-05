import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { QueryClient, QueryClientProvider, useQueryClient } from '@tanstack/react-query';
import { ClerkProvider, Show, SignIn, SignUp, useClerk, useUser } from '@clerk/react';
import { publishableKeyFromHost } from '@clerk/react/internal';
import { shadcn } from '@clerk/themes';
import {
  Activity,
  AlertOctagon,
  Ban,
  ChevronRight,
  Clock3,
  Cpu,
  Database,
  FileSearch,
  Gauge,
  Globe2,
  ListFilter,
  LockKeyhole,
  Menu,
  Minus,
  Network,
  Pause,
  Play,
  RefreshCw,
  RotateCcw,
  Server,
  ShieldCheck,
  ShieldEllipsis,
  Siren,
  TerminalSquare,
  TrendingUp,
  Unlock,
  X,
} from 'lucide-react';
import { toast } from 'sonner';
import {
  getGetSecurityOverviewQueryKey,
  getListSecurityEventsQueryKey,
  useBanAddress,
  useControlService,
  useGetSecurityOverview,
  useListSecurityEvents,
  useRefreshThreatIntel,
  useUnbanAddress,
} from '@workspace/api-client-react';
import type { SecurityEvent, SecurityOverview, SecurityOverviewServicesItem } from '@workspace/api-client-react';
import { ErrorBoundary } from '@/components/error-boundary';
import { Toaster } from '@/components/ui/toaster';
import { TooltipProvider } from '@/components/ui/tooltip';
import NotFound from '@/pages/not-found';
import { Link, Redirect, Route, Switch, Router as WouterRouter } from 'wouter';

const queryClient = new QueryClient();
const basePath = import.meta.env.BASE_URL.replace(/\/$/, '');
const clerkPubKey = publishableKeyFromHost(
  window.location.hostname,
  import.meta.env.VITE_CLERK_PUBLISHABLE_KEY,
);
const clerkProxyUrl = import.meta.env.VITE_CLERK_PROXY_URL;

const navItems = [
  { label: 'Overview', icon: Gauge, active: true },
  { label: 'Detections', icon: Siren, detail: '08' },
  { label: 'Traffic', icon: Network },
  { label: 'Response queue', icon: TerminalSquare, detail: '03' },
];

function formatUptime(seconds = 0) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return `${days}d ${hours}h ${minutes}m`;
}

function formatNumber(value = 0) {
  return new Intl.NumberFormat('en-US').format(value);
}

function timeAgo(timestamp: string) {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return 'Unknown time';
  const minutes = Math.max(0, Math.round((Date.now() - date.getTime()) / 60000));
  if (minutes < 1) return 'Just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
}

function severityTone(severity: SecurityEvent['severity']) {
  if (severity === 'critical') return 'bg-[#f8d8d2] text-[#a83426] border-[#efb6ac]';
  if (severity === 'high') return 'bg-[#fbe8cb] text-[#a35c0a] border-[#f0cf9b]';
  if (severity === 'medium') return 'bg-[#e9efc5] text-[#566713] border-[#cedb8a]';
  return 'bg-[#dbeaf0] text-[#2a6477] border-[#b5d3de]';
}

function serviceLabel(name: string) {
  return name.replace('-', ' ');
}

function OverviewSkeleton() {
  return (
    <div className="space-y-5" data-testid="loading-overview">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {[1, 2, 3, 4].map((item) => <div key={item} className="h-28 rounded-sm skeleton-shimmer" />)}
      </div>
      <div className="grid gap-5 xl:grid-cols-[1.45fr_.85fr]">
        <div className="h-72 rounded-sm skeleton-shimmer" />
        <div className="h-72 rounded-sm skeleton-shimmer" />
      </div>
      <div className="h-80 rounded-sm skeleton-shimmer" />
    </div>
  );
}

function Sidebar({ mobileOpen, onClose }: { mobileOpen: boolean; onClose: () => void }) {
  return (
    <aside className={`fixed inset-y-0 left-0 z-40 flex w-[252px] shrink-0 flex-col border-r border-[#313a4e] bg-[#20283a] text-[#eef0e7] transition-transform duration-300 lg:static lg:translate-x-0 ${mobileOpen ? 'translate-x-0' : '-translate-x-full'}`}>
      <div className="flex h-[76px] items-center justify-between border-b border-[#313a4e] px-6">
        <div className="flex items-center gap-3">
          <div className="relative flex h-8 w-8 items-center justify-center bg-[#c9ed4a] text-[#20283a]">
            <ShieldCheck size={19} strokeWidth={2.5} />
            <span className="absolute -right-1 -top-1 h-2 w-2 bg-[#f26a4e]" />
          </div>
          <div>
            <div className="font-mono-ui text-[13px] font-bold tracking-[.12em]">BASTION<span className="text-[#c9ed4a]">FW</span></div>
            <div className="mt-0.5 text-[9px] uppercase tracking-[.24em] text-[#909aae]">security console</div>
          </div>
        </div>
        <button onClick={onClose} className="text-[#909aae] hover:text-white lg:hidden" data-testid="button-close-sidebar" aria-label="Close navigation">
          <X size={19} />
        </button>
      </div>
      <div className="px-5 py-6">
        <div className="mb-3 flex items-center justify-between text-[10px] uppercase tracking-[.18em] text-[#778198]">
          <span>Workspace</span><span className="font-mono-ui text-[#566177]">01</span>
        </div>
        <nav className="space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <button key={item.label} onClick={() => toast.info(`${item.label} is represented in this live overview.`)} className={`group flex w-full items-center gap-3 border-l-2 px-3 py-3 text-left text-[13px] transition-colors ${item.active ? 'border-[#c9ed4a] bg-[#2b354b] text-white' : 'border-transparent text-[#aab2c1] hover:border-[#566177] hover:bg-[#273147] hover:text-white'}`} data-testid={`button-nav-${item.label.toLowerCase().replaceAll(' ', '-')}`}>
                <Icon size={16} className={item.active ? 'text-[#c9ed4a]' : 'text-[#8490a5]'} />
                <span className="flex-1">{item.label}</span>
                {item.detail && <span className={`font-mono-ui text-[10px] ${item.active ? 'text-[#c9ed4a]' : 'text-[#657188]'}`}>{item.detail}</span>}
              </button>
            );
          })}
        </nav>
      </div>
      <div className="mt-auto px-5 pb-5">
        <div className="border border-[#39445a] bg-[#273147] p-4">
          <div className="mb-3 flex items-center gap-2 text-[11px] font-semibold text-[#e4e7df]">
            <span className="status-pulse h-2 w-2 rounded-full bg-[#c9ed4a]" />
            Operations healthy
          </div>
          <div className="flex items-center justify-between border-t border-[#39445a] pt-3 text-[10px] text-[#8e99ae]">
            <span>Console node</span><span className="font-mono-ui text-[#c5ccd7]">BAS-01</span>
          </div>
          <div className="mt-2 flex items-center justify-between text-[10px] text-[#8e99ae]">
            <span>Build</span><span className="font-mono-ui text-[#c5ccd7]">v0.9.14</span>
          </div>
        </div>
        <div className="mt-4 flex items-center justify-between px-1 text-[10px] text-[#68748b]">
          <span>Last sync</span><span className="font-mono-ui">12 sec ago</span>
        </div>
      </div>
    </aside>
  );
}

function Header({ onMenu }: { onMenu: () => void }) {
  const { signOut } = useClerk();
  const { user } = useUser();
  return (
    <header className="flex min-h-[76px] items-center justify-between border-b border-[#ddd8cb] bg-[#faf9f4]/95 px-5 sm:px-8">
      <div className="flex items-center gap-3">
        <button onClick={onMenu} className="text-[#20283a] lg:hidden" data-testid="button-open-sidebar" aria-label="Open navigation"><Menu size={21} /></button>
        <div className="hidden items-center gap-2 text-[11px] text-[#70746f] sm:flex">
          <span>Operations</span><ChevronRight size={13} /><span className="font-semibold text-[#20283a]">Live overview</span>
        </div>
        <div className="sm:hidden font-mono-ui text-[12px] font-bold tracking-[.12em]">BASTION<span className="text-[#708810]">FW</span></div>
      </div>
      <div className="flex items-center gap-4 sm:gap-7">
        <div className="hidden items-center gap-2 text-[10px] uppercase tracking-[.14em] text-[#777b76] sm:flex">
          <span className="status-pulse h-2 w-2 rounded-full bg-[#77a10d]" /> Operator session active
        </div>
        <div className="flex items-center gap-3 border-l border-[#ddd8cb] pl-4 sm:pl-6">
          <div className="flex h-8 w-8 items-center justify-center bg-[#e5e9ce] font-mono-ui text-[11px] font-bold text-[#536311]">{(user?.firstName?.[0] ?? 'O')}{(user?.lastName?.[0] ?? 'P')}</div>
          <div className="hidden sm:block">
            <div className="text-[12px] font-semibold text-[#20283a]">{user?.fullName ?? user?.primaryEmailAddress?.emailAddress ?? 'Operator'}</div>
            <button type="button" onClick={() => signOut({ redirectUrl: basePath || '/' })} className="font-mono-ui text-[9px] uppercase tracking-[.08em] text-[#8a8d87] hover:text-[#b54731]">Sign out</button>
          </div>
        </div>
      </div>
    </header>
  );
}

function MetricCard({ label, value, detail, icon: Icon, tone = 'ink', testId }: { label: string; value: string; detail: string; icon: typeof Activity; tone?: 'ink' | 'lime' | 'orange'; testId: string }) {
  const toneClass = tone === 'lime' ? 'text-[#708810] bg-[#edf3d4]' : tone === 'orange' ? 'text-[#b54731] bg-[#f7e0d9]' : 'text-[#536175] bg-[#e7ebee]';
  return (
    <div className="group border border-[#ddd8cb] bg-[#faf9f4] p-4 transition-all hover:-translate-y-0.5 hover:border-[#b9b5aa] hover:shadow-[0_8px_18px_-14px_hsl(222_31%_15%/.35)]" data-testid={`card-${testId}`}>
      <div className="mb-4 flex items-start justify-between">
        <span className="text-[10px] font-semibold uppercase tracking-[.14em] text-[#777b76]">{label}</span>
        <span className={`flex h-7 w-7 items-center justify-center ${toneClass}`}><Icon size={14} /></span>
      </div>
      <div className="font-mono-ui text-[25px] font-bold tracking-[-.04em] text-[#20283a]" data-testid={`text-${testId}-value`}>{value}</div>
      <div className="mt-1 flex items-center gap-1.5 text-[10px] text-[#838680]"><span className="font-mono-ui text-[#5d7e0b]">{detail}</span></div>
    </div>
  );
}

function SectionHeading({ eyebrow, title, action }: { eyebrow: string; title: string; action?: ReactNode }) {
  return (
    <div className="mb-5 flex items-end justify-between">
      <div>
        <div className="mb-1.5 font-mono-ui text-[9px] uppercase tracking-[.18em] text-[#81900f]">{eyebrow}</div>
        <h2 className="text-[17px] font-bold tracking-[-.02em] text-[#20283a]">{title}</h2>
      </div>
      {action}
    </div>
  );
}

function PostureCard({ overview }: { overview: SecurityOverview }) {
  const isEnforcing = overview.mode === 'ENFORCING';
  return (
    <div className="relative overflow-hidden border border-[#303a4e] bg-[#20283a] p-5 text-[#eef0e7] sm:p-6" data-testid="card-protection-posture">
      <div className="absolute -right-8 -top-10 h-40 w-40 rounded-full border-[18px] border-[#33405a] opacity-50" />
      <div className="absolute -right-2 -top-4 h-24 w-24 rounded-full border border-[#c9ed4a]/40" />
      <div className="relative">
        <div className="mb-5 flex items-start justify-between">
          <div>
            <div className="mb-2 flex items-center gap-2 font-mono-ui text-[9px] uppercase tracking-[.18em] text-[#a2adbd]"><ShieldEllipsis size={13} className="text-[#c9ed4a]" /> Protection posture</div>
            <div className="text-[28px] font-bold tracking-[-.05em] text-white" data-testid="text-protection-mode">{isEnforcing ? 'Active defense' : 'Observation mode'}</div>
          </div>
          <div className={`flex items-center gap-1.5 border px-2.5 py-1.5 font-mono-ui text-[9px] uppercase tracking-[.12em] ${isEnforcing ? 'border-[#607322] bg-[#33431c] text-[#c9ed4a]' : 'border-[#a35c0a] bg-[#4c371f] text-[#f1bc72]'}`} data-testid="status-protection-mode">
            <span className={`h-1.5 w-1.5 rounded-full ${isEnforcing ? 'bg-[#c9ed4a] status-pulse' : 'bg-[#f1bc72]'}`} /> {overview.mode}
          </div>
        </div>
        <p className="max-w-[460px] text-[12px] leading-5 text-[#b6bfca]">{isEnforcing ? 'Rules are actively blocking hostile traffic across all protected sources.' : 'Rules are observing traffic only. No automatic blocks will be issued.'}</p>
        <div className="mt-6 grid grid-cols-2 gap-3 border-t border-[#3c465a] pt-4 sm:grid-cols-3">
          <div><div className="mb-1 text-[9px] uppercase tracking-[.14em] text-[#8490a5]">Uptime</div><div className="font-mono-ui text-[12px] text-[#eef0e7]">{formatUptime(overview.uptimeSeconds)}</div></div>
          <div><div className="mb-1 text-[9px] uppercase tracking-[.14em] text-[#8490a5]">Queue depth</div><div className={`font-mono-ui text-[12px] ${overview.queueDepth > 50 ? 'text-[#f1bc72]' : 'text-[#eef0e7]'}`}>{formatNumber(overview.queueDepth)} events</div></div>
          <div className="col-span-2 sm:col-span-1"><div className="mb-1 text-[9px] uppercase tracking-[.14em] text-[#8490a5]">Protected sources</div><div className="font-mono-ui text-[12px] text-[#eef0e7]">{formatNumber(overview.protectedSources)} endpoints</div></div>
        </div>
      </div>
    </div>
  );
}

function TrafficPanel({ overview }: { overview: SecurityOverview }) {
  const maxRequests = Math.max(...overview.traffic.map((point) => point.requests), 1);
  return (
    <div className="border border-[#ddd8cb] bg-[#faf9f4] p-5 sm:p-6" data-testid="card-traffic-analytics">
      <SectionHeading eyebrow="Signal / 24 hours" title="Traffic analytics" action={<span className="font-mono-ui text-[10px] text-[#888c86]">{formatNumber(overview.eventsPerMinute)} epm</span>} />
      <div className="flex h-[164px] items-end gap-1.5 border-b border-l border-[#ddd8cb] px-2 pb-0 pt-4 sm:gap-2.5">
        {overview.traffic.length === 0 ? <div className="flex h-full w-full items-center justify-center text-[11px] text-[#8b8f89]" data-testid="empty-traffic">No traffic samples available</div> : overview.traffic.map((point, index) => {
          const requestHeight = Math.max(8, (point.requests / maxRequests) * 132);
          const blockedHeight = Math.max(3, (point.blocked / maxRequests) * 132);
          return (
            <div key={`${point.label}-${index}`} className="group relative flex h-full flex-1 items-end justify-center gap-[2px]" title={`${point.label}: ${formatNumber(point.requests)} requests, ${formatNumber(point.blocked)} blocked`} data-testid={`bar-traffic-${index}`}>
              <div className="w-[45%] max-w-4 bg-[#bac9d0] transition-all group-hover:bg-[#8eabb6]" style={{ height: `${requestHeight}px` }} />
              <div className="w-[45%] max-w-4 bg-[#c9ed4a] transition-all group-hover:bg-[#a9ce2c]" style={{ height: `${blockedHeight}px` }} />
              <span className="absolute -bottom-5 whitespace-nowrap font-mono-ui text-[8px] text-[#92958f]">{point.label}</span>
            </div>
          );
        })}
      </div>
      <div className="mt-8 flex items-center gap-5 text-[10px] text-[#777b76]"><span className="flex items-center gap-1.5"><i className="h-2 w-2 bg-[#bac9d0]" /> Requests</span><span className="flex items-center gap-1.5"><i className="h-2 w-2 bg-[#c9ed4a]" /> Blocked</span></div>
    </div>
  );
}

function AttackPanel({ overview }: { overview: SecurityOverview }) {
  const total = overview.attackCounts.reduce((sum, item) => sum + item.count, 0);
  return (
    <div className="border border-[#ddd8cb] bg-[#faf9f4] p-5 sm:p-6" data-testid="card-attack-breakdown">
      <SectionHeading eyebrow="Classification" title="Attack breakdown" action={<span className="font-mono-ui text-[10px] text-[#888c86]">{formatNumber(total)} total</span>} />
      {overview.attackCounts.length === 0 ? <div className="flex h-44 items-center justify-center border border-dashed border-[#d5d0c4] text-[11px] text-[#8b8f89]" data-testid="empty-attacks">No attack classifications yet</div> : (
        <div className="space-y-4" data-testid="list-attack-breakdown">
          {overview.attackCounts.map((attack, index) => {
            const percentage = total ? (attack.count / total) * 100 : 0;
            return (
              <div key={`${attack.label}-${index}`} data-testid={`row-attack-${index}`}>
                <div className="mb-1.5 flex items-center justify-between text-[11px]"><span className="font-medium text-[#555d5b]">{attack.label}</span><span className="font-mono-ui text-[#20283a]">{formatNumber(attack.count)}</span></div>
                <div className="h-1.5 bg-[#ebe8df]"><div className="h-full transition-all duration-700" style={{ width: `${Math.max(percentage, 2)}%`, backgroundColor: attack.color || '#c9ed4a' }} /></div>
              </div>
            );
          })}
        </div>
      )}
      <div className="mt-6 grid grid-cols-2 gap-2 border-t border-[#e0dcd1] pt-4">
        <div><div className="text-[9px] uppercase tracking-[.12em] text-[#858981]">Blocked IPs</div><div className="mt-1 font-mono-ui text-[16px] font-bold text-[#20283a]" data-testid="text-blocked-ips">{formatNumber(overview.ipsBlocked)}</div></div>
        <div><div className="text-[9px] uppercase tracking-[.12em] text-[#858981]">Pipeline errors</div><div className={`mt-1 font-mono-ui text-[16px] font-bold ${overview.pipelineErrors ? 'text-[#b54731]' : 'text-[#20283a]'}`} data-testid="text-pipeline-errors">{formatNumber(overview.pipelineErrors)}</div></div>
      </div>
    </div>
  );
}

function EventsPanel({ events, isLoading, isError, onRetry }: { events: SecurityEvent[] | undefined; isLoading: boolean; isError: boolean; onRetry: () => void }) {
  return (
    <div className="border border-[#ddd8cb] bg-[#faf9f4]" data-testid="card-recent-detections">
      <div className="flex items-center justify-between border-b border-[#ddd8cb] px-5 py-5 sm:px-6">
        <SectionHeading eyebrow="Incoming / prioritized" title="Recent detections" />
        <button onClick={() => toast.info('Detection stream filter', { description: 'Showing all severities in priority order.' })} className="flex items-center gap-1.5 border border-[#d7d2c6] px-3 py-2 text-[10px] font-semibold text-[#59605e] transition-colors hover:border-[#20283a] hover:bg-[#20283a] hover:text-white" data-testid="button-filter-events"><ListFilter size={13} /> Filter</button>
      </div>
      {isLoading ? <div className="space-y-3 p-5" data-testid="loading-events">{[1, 2, 3, 4].map((item) => <div key={item} className="h-12 skeleton-shimmer" />)}</div> : isError ? (
        <div className="flex min-h-[220px] flex-col items-center justify-center px-5 text-center" data-testid="error-events"><AlertOctagon size={22} className="mb-3 text-[#b54731]" /><div className="text-[13px] font-semibold text-[#20283a]">Detection stream unavailable</div><p className="mt-1 text-[11px] text-[#81857e]">The latest signals could not be loaded.</p><button onClick={onRetry} className="mt-4 border border-[#d7d2c6] px-3 py-2 text-[10px] font-semibold hover:border-[#20283a]" data-testid="button-retry-events">Retry stream</button></div>
      ) : !events?.length ? <div className="flex min-h-[220px] flex-col items-center justify-center text-center" data-testid="empty-events"><FileSearch size={24} className="mb-3 text-[#9aa096]" /><div className="text-[13px] font-semibold text-[#20283a]">No recent detections</div><p className="mt-1 text-[11px] text-[#81857e]">The stream is quiet. New signals will appear here.</p></div> : (
        <div className="divide-y divide-[#e7e3d9]" data-testid="list-security-events">
          {events.map((event) => (
            <div key={event.id} className="group grid gap-3 px-5 py-4 transition-colors hover:bg-[#f3f2ea] sm:grid-cols-[86px_1fr_125px_118px] sm:items-center sm:px-6" data-testid={`row-event-${event.id}`}>
              <div className={`w-fit border px-2 py-1 font-mono-ui text-[9px] uppercase tracking-[.08em] ${severityTone(event.severity)}`} data-testid={`status-event-severity-${event.id}`}>{event.severity}</div>
              <div className="min-w-0"><div className="truncate text-[12px] font-semibold text-[#30394a]">{event.rule}</div><div className="mt-1 flex items-center gap-2 truncate text-[10px] text-[#81857e]"><span className="font-mono-ui text-[#59605e]">{event.ip}</span><span className="text-[#c4c0b7]">/</span><span className="truncate">{event.source}</span></div></div>
              <div className="flex items-center gap-1.5 text-[10px] text-[#81857e]"><Clock3 size={12} /> {timeAgo(event.timestamp)}</div>
              <div className="flex items-center justify-between sm:justify-end sm:gap-3"><span className="flex items-center gap-1.5 text-[10px] font-semibold capitalize text-[#687069]"><span className={`h-1.5 w-1.5 rounded-full ${event.status === 'blocked' ? 'bg-[#77a10d]' : event.status === 'mitigated' ? 'bg-[#2a6477]' : 'bg-[#d69126]'}`} />{event.status}</span><button onClick={() => toast.info(event.rule, { description: event.evidence || `${event.source} · ${event.ip}` })} className="text-[#9ba099] opacity-0 transition-opacity hover:text-[#20283a] group-hover:opacity-100" aria-label={`Inspect ${event.rule}`} data-testid={`button-inspect-event-${event.id}`}><ChevronRight size={16} /></button></div>
            </div>
          ))}
        </div>
      )}
      <div className="flex items-center justify-between border-t border-[#ddd8cb] px-5 py-3.5 sm:px-6"><span className="font-mono-ui text-[9px] uppercase tracking-[.12em] text-[#8a8e87]">Showing latest {events?.length ?? 0} signals</span><span className="flex items-center gap-1 font-mono-ui text-[9px] text-[#6d850d]"><Activity size={11} /> Stream live</span></div>
    </div>
  );
}

function ResponsePanel({ overview }: { overview: SecurityOverview }) {
  const queryClient = useQueryClient();
  const [address, setAddress] = useState('');
  const [pendingIp, setPendingIp] = useState<string | null>(null);
  const [pendingService, setPendingService] = useState<string | null>(null);
  const ban = useBanAddress();
  const unban = useUnbanAddress();
  const control = useControlService();
  const refreshIntel = useRefreshThreatIntel();
  const addresses = useMemo(() => overview.blockedAddresses ?? [], [overview.blockedAddresses]);

  const invalidateOverview = () => {
    queryClient.invalidateQueries({ queryKey: getGetSecurityOverviewQueryKey() });
    queryClient.invalidateQueries({ queryKey: getListSecurityEventsQueryKey({ limit: 8 }) });
  };
  const submitBan = () => {
    const ip = address.trim();
    if (ip.length < 7) {
      toast.error('Enter a valid address before staging a ban.');
      return;
    }
    setPendingIp(ip);
    ban.mutate({ data: { ip } }, {
      onSuccess: (result) => {
        toast.success(result.message || `Ban staged for ${ip}`, { description: `Mode: ${result.mode}` });
        setAddress('');
        invalidateOverview();
      },
      onError: () => toast.error(`Could not stage a ban for ${ip}`),
      onSettled: () => setPendingIp(null),
    });
  };
  const submitUnban = (ip: string) => {
    setPendingIp(ip);
    unban.mutate({ data: { ip } }, {
      onSuccess: (result) => { toast.success(result.message || `Unban staged for ${ip}`); invalidateOverview(); },
      onError: () => toast.error(`Could not stage an unban for ${ip}`),
      onSettled: () => setPendingIp(null),
    });
  };
  const submitServiceAction = (service: string, action: 'start' | 'stop' | 'restart') => {
    setPendingService(`${service}-${action}`);
    control.mutate({ data: { service: service as 'sentinel' | 'firewall' | 'threat-intel', action } }, {
      onSuccess: (result) => { toast.success(result.message || `${serviceLabel(service)} ${action} staged`, { description: `Mode: ${result.mode}` }); invalidateOverview(); },
      onError: () => toast.error(`Could not ${action} ${serviceLabel(service)}`),
      onSettled: () => setPendingService(null),
    });
  };
  const submitIntelRefresh = () => {
    refreshIntel.mutate(undefined, {
      onSuccess: (result) => { toast.success(result.message || 'Threat intelligence refresh staged'); invalidateOverview(); },
      onError: () => toast.error('Threat intelligence refresh failed'),
    });
  };

  return (
    <div className="grid gap-5 xl:grid-cols-[1fr_1fr]" data-testid="section-response-controls">
      <div className="border border-[#ddd8cb] bg-[#faf9f4] p-5 sm:p-6">
        <SectionHeading eyebrow="Manual intervention" title="Address controls" action={<Ban size={16} className="text-[#b54731]" />} />
        <div className="mb-4 border-l-2 border-[#f26a4e] bg-[#f9ebe7] px-3 py-2.5 text-[10px] leading-4 text-[#854433]"><strong className="font-semibold">Safe staging:</strong> Actions respect the current {overview.mode} policy and are recorded for audit.</div>
        <div className="flex gap-2">
          <input value={address} onChange={(event) => setAddress(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter') submitBan(); }} placeholder="IPv4 or IPv6 address" className="min-w-0 flex-1 border border-[#d7d2c6] bg-[#fffef9] px-3 py-2.5 font-mono-ui text-[11px] text-[#20283a] outline-none transition-colors placeholder:text-[#a2a49e] focus:border-[#829d16] focus:ring-2 focus:ring-[#c9ed4a]/35" data-testid="input-address-ban" />
          <button onClick={submitBan} disabled={!!pendingIp} className="flex items-center gap-2 bg-[#20283a] px-3.5 py-2.5 text-[10px] font-semibold text-[#f8f8ef] transition-colors hover:bg-[#303b51] disabled:cursor-wait disabled:opacity-60" data-testid="button-ban-address"><Ban size={13} /> {pendingIp === address.trim() ? 'Staging' : 'Stage ban'}</button>
        </div>
        <div className="mt-5 mb-2 flex items-center justify-between"><span className="text-[10px] font-semibold uppercase tracking-[.13em] text-[#777b76]">Blocked addresses</span><span className="font-mono-ui text-[10px] text-[#8a8e87]">{addresses.length} active</span></div>
        <div className="max-h-[176px] overflow-auto border border-[#e2ded4]">
          {addresses.length === 0 ? <div className="px-3 py-5 text-center text-[11px] text-[#8b8f89]" data-testid="empty-blocked-addresses">No addresses currently blocked.</div> : addresses.map((ip) => <div key={ip} className="flex items-center justify-between border-b border-[#ebe7de] px-3 py-2.5 last:border-0 hover:bg-[#f3f2ea]" data-testid={`row-blocked-address-${ip}`}><span className="font-mono-ui text-[11px] text-[#4f5859]">{ip}</span><button onClick={() => submitUnban(ip)} disabled={!!pendingIp} className="flex items-center gap-1 text-[10px] font-semibold text-[#7c8580] hover:text-[#b54731] disabled:opacity-50" data-testid={`button-unban-${ip}`}><Unlock size={12} /> Unban</button></div>)}
        </div>
      </div>
      <div className="border border-[#ddd8cb] bg-[#faf9f4] p-5 sm:p-6">
        <SectionHeading eyebrow="Control plane" title="Service controls" action={<Cpu size={16} className="text-[#536175]" />} />
        <div className="space-y-2.5">
          {overview.services.map((service: SecurityOverviewServicesItem) => {
            const serviceKey = service.name.toLowerCase().replaceAll(' ', '-');
            const isPending = pendingService?.startsWith(serviceKey);
            return <div key={service.name} className="border border-[#e2ded4] px-3.5 py-3 transition-colors hover:border-[#c8c2b4]" data-testid={`row-service-${serviceKey}`}>
              <div className="flex items-start justify-between gap-3"><div className="flex min-w-0 items-start gap-2.5"><span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${service.state === 'running' ? 'status-pulse bg-[#77a10d]' : service.state === 'degraded' ? 'bg-[#d69126]' : 'bg-[#a5aaa5]'}`} /><div><div className="text-[12px] font-semibold capitalize text-[#30394a]">{service.name}</div><div className="mt-0.5 truncate text-[10px] text-[#868a84]">{service.detail}</div></div></div><span className="font-mono-ui text-[9px] uppercase text-[#79817d]">{service.state}</span></div>
              <div className="mt-3 flex gap-1.5 border-t border-[#ebe7de] pt-2.5">
                {(['start', 'stop', 'restart'] as const).map((action) => <button key={action} onClick={() => submitServiceAction(serviceKey, action)} disabled={!!isPending} className="flex items-center gap-1 border border-[#dcd8ce] px-2 py-1.5 text-[9px] font-semibold capitalize text-[#68706e] transition-colors hover:border-[#20283a] hover:bg-[#20283a] hover:text-white disabled:opacity-45" data-testid={`button-${action}-service-${serviceKey}`}>{action === 'start' ? <Play size={10} /> : action === 'stop' ? <Pause size={10} /> : <RotateCcw size={10} />}{isPending && pendingService === `${serviceKey}-${action}` ? 'Sending' : action}</button>)}
              </div>
            </div>;
          })}
          {overview.services.length === 0 && <div className="py-8 text-center text-[11px] text-[#8b8f89]" data-testid="empty-services">No service telemetry available.</div>}
        </div>
      </div>
      <div className="border border-[#ddd8cb] bg-[#faf9f4] p-5 sm:p-6 xl:col-span-2">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3"><div className="flex h-9 w-9 items-center justify-center bg-[#e9efc5] text-[#65790d]"><Globe2 size={17} /></div><div><div className="text-[12px] font-semibold text-[#30394a]">Threat intelligence feed</div><div className="mt-1 text-[10px] text-[#858981]"><span className="capitalize">{overview.threatIntel.status}</span> · {overview.threatIntel.provider} · refreshed {timeAgo(overview.threatIntel.lastRefresh)}</div></div></div>
          <button onClick={submitIntelRefresh} disabled={refreshIntel.isPending} className="flex items-center gap-2 border border-[#d7d2c6] px-3 py-2 text-[10px] font-semibold text-[#59605e] transition-colors hover:border-[#20283a] hover:bg-[#20283a] hover:text-white disabled:opacity-50" data-testid="button-refresh-threat-intel"><RefreshCw size={13} className={refreshIntel.isPending ? 'animate-spin' : ''} /> {refreshIntel.isPending ? 'Refreshing' : 'Refresh feed'}</button>
        </div>
      </div>
    </div>
  );
}

function Dashboard() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const overviewQuery = useGetSecurityOverview({ query: { refetchInterval: 15000, queryKey: getGetSecurityOverviewQueryKey() } });
  const eventsQuery = useListSecurityEvents({ limit: 8 });

  return (
    <div className="min-h-[100dvh] bg-[#f2f0e8] text-[#20283a]">
      <div className="flex min-h-[100dvh]">
        <Sidebar mobileOpen={mobileOpen} onClose={() => setMobileOpen(false)} />
        {mobileOpen && <button className="fixed inset-0 z-30 bg-[#20283a]/35 lg:hidden" onClick={() => setMobileOpen(false)} aria-label="Close navigation overlay" data-testid="button-close-sidebar-overlay" />}
        <main className="min-w-0 flex-1">
          <Header onMenu={() => setMobileOpen(true)} />
          <div className="cockpit-grid scanline min-h-[calc(100dvh-76px)] px-4 py-6 sm:px-8 sm:py-8">
            <div className="mx-auto max-w-[1500px]">
              <div className="mb-7 flex flex-wrap items-end justify-between gap-4 rise-in">
                <div><div className="mb-2 flex items-center gap-2 font-mono-ui text-[10px] uppercase tracking-[.2em] text-[#81900f]"><span className="status-pulse h-1.5 w-1.5 rounded-full bg-[#77a10d]" /> Live operations snapshot</div><h1 className="text-[28px] font-bold tracking-[-.055em] text-[#20283a] sm:text-[36px]" data-testid="heading-security-overview">Security overview</h1><p className="mt-2 text-[12px] text-[#777b76]">Understand the perimeter. Make the next safe move.</p></div>
                <div className="flex items-center gap-2 border border-[#d8d4c8] bg-[#faf9f4] px-3 py-2 font-mono-ui text-[9px] uppercase tracking-[.12em] text-[#777b76]" data-testid="status-console-sync"><span className="h-1.5 w-1.5 rounded-full bg-[#77a10d]" /> Auto-refresh 15s</div>
              </div>
              {overviewQuery.isLoading ? <OverviewSkeleton /> : overviewQuery.isError || !overviewQuery.data ? <div className="flex min-h-[400px] flex-col items-center justify-center border border-[#ddd8cb] bg-[#faf9f4] text-center" data-testid="error-overview"><AlertOctagon size={28} className="mb-4 text-[#b54731]" /><div className="text-[16px] font-semibold text-[#20283a]">Overview telemetry unavailable</div><p className="mt-2 max-w-sm text-[12px] text-[#81857e]">BastionFW could not reach the operations API. Retry when the control plane is ready.</p><button onClick={() => overviewQuery.refetch()} className="mt-5 flex items-center gap-2 bg-[#20283a] px-4 py-2.5 text-[11px] font-semibold text-[#faf9f4] hover:bg-[#303b51]" data-testid="button-retry-overview"><RefreshCw size={13} /> Retry telemetry</button></div> : (
                <div className="space-y-5">
                  <div className="grid grid-cols-2 gap-3 lg:grid-cols-4 rise-in rise-in-delay-1">
                    <MetricCard label="Logs processed" value={formatNumber(overviewQuery.data.logsProcessed)} detail="within last 24 hours" icon={Database} tone="ink" testId="logs-processed" />
                    <MetricCard label="Threats detected" value={formatNumber(overviewQuery.data.threatsDetected)} detail="signals triaged" icon={Siren} tone="orange" testId="threats-detected" />
                    <MetricCard label="IPs blocked" value={formatNumber(overviewQuery.data.ipsBlocked)} detail="active perimeter blocks" icon={Ban} tone="lime" testId="ips-blocked" />
                    <MetricCard label="Events / minute" value={formatNumber(overviewQuery.data.eventsPerMinute)} detail="current ingest rate" icon={TrendingUp} tone="ink" testId="events-per-minute" />
                  </div>
                  <div className="grid gap-5 xl:grid-cols-[1.12fr_.88fr] rise-in rise-in-delay-2"><PostureCard overview={overviewQuery.data} /><div className="grid gap-5 md:grid-cols-2 xl:grid-cols-1"><TrafficPanel overview={overviewQuery.data} /><AttackPanel overview={overviewQuery.data} /></div></div>
                  <div className="rise-in rise-in-delay-3"><EventsPanel events={eventsQuery.data} isLoading={eventsQuery.isLoading} isError={eventsQuery.isError} onRetry={() => eventsQuery.refetch()} /></div>
                  <div className="pt-2 rise-in rise-in-delay-3"><div className="mb-4 flex items-center gap-3"><div className="h-px flex-1 bg-[#ddd8cb]" /><span className="font-mono-ui text-[9px] uppercase tracking-[.2em] text-[#8a8e87]">Response controls</span><div className="h-px flex-1 bg-[#ddd8cb]" /></div><ResponsePanel overview={overviewQuery.data} /></div>
                  <footer className="flex flex-wrap items-center justify-between gap-3 border-t border-[#ddd8cb] pt-5 text-[10px] text-[#8b8f89]"><span className="flex items-center gap-1.5"><LockKeyhole size={12} /> Actions are staged, logged, and policy-aware.</span><span className="font-mono-ui">BASTIONFW / INTERNAL USE</span></footer>
                </div>
              )}
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}

function Landing() {
  return (
    <main className="min-h-[100dvh] bg-[#20283a] text-[#eef0e7]">
      <div className="mx-auto flex min-h-[100dvh] max-w-5xl flex-col justify-between px-6 py-8 sm:px-10">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center bg-[#c9ed4a] text-[#20283a]"><ShieldCheck size={20} /></div>
          <div><div className="font-mono-ui text-sm font-bold tracking-[.14em]">BASTION<span className="text-[#c9ed4a]">FW</span></div><div className="text-[9px] uppercase tracking-[.2em] text-[#909aae]">security console</div></div>
        </div>
        <div className="max-w-2xl py-20">
          <div className="mb-5 flex items-center gap-2 font-mono-ui text-[10px] uppercase tracking-[.2em] text-[#c9ed4a]"><span className="status-pulse h-1.5 w-1.5 rounded-full bg-[#c9ed4a]" /> Protected access</div>
          <h1 className="text-5xl font-bold tracking-[-.06em] text-white sm:text-7xl">See the perimeter.<br /><span className="text-[#c9ed4a]">Make the next safe move.</span></h1>
          <p className="mt-7 max-w-lg text-sm leading-7 text-[#b6bfca]">BastionFW is a defensive operations console for reviewing detections, understanding traffic, and staging policy-aware response actions.</p>
          <div className="mt-9 flex flex-wrap items-center gap-3">
            <Link href="/sign-in" className="inline-flex items-center gap-2 bg-[#c9ed4a] px-5 py-3 text-sm font-semibold text-[#20283a] transition-transform hover:-translate-y-0.5">Sign in to console <ChevronRight size={16} /></Link>
            <span className="font-mono-ui text-[10px] uppercase tracking-[.14em] text-[#909aae]">Clerk protected · dry-run by default</span>
          </div>
        </div>
        <div className="flex flex-wrap gap-x-8 gap-y-3 border-t border-[#3c465a] pt-5 font-mono-ui text-[10px] uppercase tracking-[.12em] text-[#8490a5]"><span>Live detection review</span><span>Staged response controls</span><span>Audit-aware posture</span></div>
      </div>
    </main>
  );
}

function SignInPage() {
  return <div className="flex min-h-[100dvh] items-center justify-center bg-[#20283a] px-4"><SignIn routing="path" path={`${basePath}/sign-in`} signUpUrl={`${basePath}/sign-up`} /></div>;
}

function SignUpPage() {
  return <div className="flex min-h-[100dvh] items-center justify-center bg-[#20283a] px-4"><SignUp routing="path" path={`${basePath}/sign-up`} signInUrl={`${basePath}/sign-in`} /></div>;
}

function HomeRedirect() {
  return <><Show when="signed-in"><Redirect to="/console" /></Show><Show when="signed-out"><Landing /></Show></>;
}

function ProtectedDashboard() {
  return <><Show when="signed-in"><Dashboard /></Show><Show when="signed-out"><Redirect to="/" /></Show></>;
}

function Router() {
  return <Switch><Route path="/" component={HomeRedirect} /><Route path="/sign-in/*?" component={SignInPage} /><Route path="/sign-up/*?" component={SignUpPage} /><Route path="/console" component={ProtectedDashboard} /><Route component={NotFound} /></Switch>;
}

function ClerkQueryClientCacheInvalidator() {
  const { addListener } = useClerk();
  const previousUserId = useRef<string | null | undefined>(undefined);
  useEffect(() => addListener(({ user }) => {
    const nextUserId = user?.id ?? null;
    if (previousUserId.current !== undefined && previousUserId.current !== nextUserId) queryClient.clear();
    previousUserId.current = nextUserId;
  }), [addListener]);
  return null;
}

function App() {
  if (!clerkPubKey) throw new Error('Missing VITE_CLERK_PUBLISHABLE_KEY in the environment.');
  return <WouterRouter base={basePath}><ClerkProvider publishableKey={clerkPubKey} proxyUrl={clerkProxyUrl} appearance={{
    theme: shadcn,
    cssLayerName: 'clerk',
    options: { logoPlacement: 'inside', logoLinkUrl: basePath || '/', logoImageUrl: `${window.location.origin}${basePath}/logo.svg` },
    variables: { colorPrimary: '#c9ed4a', colorForeground: '#eef0e7', colorMutedForeground: '#909aae', colorBackground: '#273147', colorInput: '#20283a', colorInputForeground: '#eef0e7', colorDanger: '#f26a4e', colorNeutral: '#566177', fontFamily: 'DM Sans, sans-serif', borderRadius: '0px' },
    elements: {
      rootBox: 'w-full flex justify-center',
      cardBox: 'bg-[#273147] rounded-none w-[440px] max-w-full overflow-hidden',
      card: '!shadow-none !border-0 !bg-transparent !rounded-none',
      footer: '!shadow-none !border-0 !bg-transparent !rounded-none',
      headerTitle: 'text-white',
      headerSubtitle: 'text-[#b6bfca]',
      socialButtonsBlockButtonText: 'text-white',
      formFieldLabel: 'text-[#d8dee7]',
      footerActionLink: 'text-[#c9ed4a]',
      footerActionText: 'text-[#909aae]',
      dividerText: 'text-[#909aae]',
      formButtonPrimary: 'bg-[#c9ed4a] text-[#20283a] hover:bg-[#d7f36d]',
      formFieldInput: 'bg-[#20283a] text-white border-[#566177]',
      main: 'bg-transparent',
    },
  }} signInUrl={`${basePath}/sign-in`} signUpUrl={`${basePath}/sign-up`}>
    <QueryClientProvider client={queryClient}><ClerkQueryClientCacheInvalidator /><TooltipProvider><ErrorBoundary><Router /></ErrorBoundary><Toaster /></TooltipProvider></QueryClientProvider>
  </ClerkProvider></WouterRouter>;
}

export default App;