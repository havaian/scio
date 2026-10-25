<script setup lang="ts">
import { computed } from 'vue';
import Card from '@/components/ui/Card.vue';
import CardHeader from '@/components/ui/CardHeader.vue';
import CardContent from '@/components/ui/CardContent.vue';
import StatusBadge from '@/components/ui/StatusBadge.vue';
import LatencyChart from '@/components/LatencyChart.vue';
import { CircleSlash } from 'lucide-vue-next';
import { inBank, store } from '@/lib/store';
import { accessOf } from '@/lib/utils';

const r = computed(() => store.report!);
const withStats = computed(() => r.value.targets.filter((t) => t.endpointStats.length && inBank(t.id)));
const th = computed(() => r.value.thresholds);
// Targets with no timing at all still get a card that says why (spec only, no HTTP answer, journey stopped early).
const noStats = computed(() => r.value.targets.filter((t) => !t.endpointStats.length && inBank(t.id)));
function whyNoData(t: { id: string }): string {
  const fs = r.value.findings.filter((f) => f.targetId === t.id && (f.checkId === 'lat.p95' || f.checkId === 'rel.availability') && f.status !== 'pass' && f.status !== 'fail');
  return fs[fs.length - 1]?.message ?? 'Only a discovery or front-door check ran for this target, so there were no repeated calls to time.';
}
const ok = (s: { availabilityPct: number; errorRatePct: number; samples: number; p95: number; p50: number }) =>
  s.availabilityPct >= th.value.availabilityPct && s.errorRatePct <= th.value.errorRatePct && (s.samples >= th.value.latencyMinSamples ? s.p95 : s.p50) <= th.value.latencyP95Ms;
// Consent journey friction (sandbox banks): one row per bank whose login was attempted, fewest steps first.
interface Journey {
  completed: boolean;
  via: 'browser' | 'form';
  screens: number;
  typed: { user: number; password: number; otp: number };
  typedTotal: number;
  choices: number;
  clicks: number;
  navigations: number;
  hosts: string[];
  tppSteps: number;
  tppStepNames: string[];
  extraLogins?: number;
  extraLoginsCompleted?: number;
}
const journeys = computed(() =>
  r.value.findings
    .filter((f) => f.checkId === 'ux.consent-journey' && f.evidence && inBank(f.targetId))
    .map((f) => ({ id: f.targetId, name: r.value.targets.find((t) => t.id === f.targetId)?.name ?? f.targetId, j: f.evidence as Journey }))
    .sort((a, b) => Number(b.j.completed) - Number(a.j.completed) || a.j.screens + a.j.tppSteps - (b.j.screens + b.j.tppSteps)),
);
// Monitor latency, last 24 h: many light samples per bank, so real banks get a latency figure resting on enough calls. Not scored.
const names = computed(() => Object.fromEntries(r.value.targets.map((t) => [t.id, t.name])));
const monitorLatency = computed(() =>
  (r.value.uptime?.targets ?? [])
    .filter((u) => u.latency24h?.samples && inBank(u.targetId))
    .map((u) => ({ id: u.targetId, name: names.value[u.targetId] ?? u.name ?? u.targetId, ...u.latency24h! }))
    .sort((a, b) => (a.p95 ?? a.p50 ?? 0) - (b.p95 ?? b.p50 ?? 0)),
);
const DESC: Record<string, string> = {
  mock: 'Authenticated reads through the full consent flow (organizers\' mock)',
  full: 'Authenticated reads through the full consent flow',
  bis: 'Authenticated reads with a client-credentials token (TBC BIS)',
  sandbox: 'Timing from the sandbox journey calls (consent, authorisation, token, account reads); median judged, as each runs once per audit',
  pending: 'Read-only front-door calls while the sandbox certificates are pending',
  probes: 'Read-only, unauthenticated front-door calls',
  spec: 'No live calls (published spec only)',
};
</script>

<template>
  <div class="space-y-6">
    <p class="text-sm leading-relaxed text-muted-foreground">
      Per bank and per API: availability, error rate and response times from repeated calls during the run.
      Thresholds are {{ th.source }}: availability ≥ {{ th.availabilityPct }}%, errors ≤ {{ th.errorRatePct }}%, p95 ≤ {{ th.latencyP95Ms }} ms (p95 needs ≥ {{ th.latencyMinSamples }} calls; below that the median is judged).
      Times are measured from the auditor's location; server p50 is the bank-reported processing time (Server-Timing).
    </p>

    <Card v-if="journeys.length">
      <CardHeader title="Consent journey" description="What a person and a TPP must do to authorise account access at each bank's sandbox (redirect SCA with the bank's demo user). Counted once per distinct screen; informational, not scored." />
      <CardContent>
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="border-b border-border text-left text-xs text-muted-foreground">
                <th class="py-2 font-medium">Bank</th>
                <th class="px-2 text-right font-medium">Screens</th>
                <th class="px-2 text-right font-medium" title="user / password / OTP">Typed</th>
                <th class="px-2 text-right font-medium">Choices</th>
                <th class="px-2 text-right font-medium">Presses</th>
                <th class="px-2 text-right font-medium">Page loads</th>
                <th class="px-2 text-right font-medium">Hosts</th>
                <th class="px-2 text-right font-medium">TPP API steps</th>
                <th class="px-2 font-medium">Result</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="x in journeys" :key="x.id" class="border-b border-border last:border-0">
                <td class="py-2">{{ x.name }}</td>
                <td class="px-2 text-right tabular-nums">{{ x.j.screens }}</td>
                <td class="px-2 text-right tabular-nums" :title="`user ${x.j.typed.user}, password ${x.j.typed.password}, OTP ${x.j.typed.otp}`">{{ x.j.typedTotal }}</td>
                <td class="px-2 text-right tabular-nums">{{ x.j.choices }}</td>
                <td class="px-2 text-right tabular-nums">{{ x.j.clicks }}</td>
                <td class="px-2 text-right tabular-nums">{{ x.j.navigations }}</td>
                <td class="px-2 text-right tabular-nums" :title="x.j.hosts.join(', ')">{{ x.j.hosts.length }}</td>
                <td class="px-2 text-right tabular-nums" :title="x.j.tppStepNames.join(' -> ')">{{ x.j.tppSteps }}</td>
                <td class="px-2 text-xs" :class="x.j.completed ? '' : 'text-muted-foreground'">{{ x.j.completed ? 'Completed' : 'Stopped' }}<span v-if="x.j.extraLogins" class="text-muted-foreground" :title="`Second consent: ${x.j.extraLoginsCompleted ?? 0} of ${x.j.extraLogins} further login(s) completed; not counted in the row`"> (+{{ x.j.extraLogins }} login)</span></td>
              </tr>
            </tbody>
          </table>
        </div>
        <p class="mt-3 text-xs leading-relaxed text-muted-foreground">Result shows whether the journey reached the return to the TPP; a stopped journey counts only the screens before the stop. Hover a cell for details.</p>
      </CardContent>
    </Card>

    <Card v-if="monitorLatency.length">
      <CardHeader title="Monitor latency, last 24 h" :description="`The uptime monitor's light front-door request, every ${r.uptime?.intervals?.realMin ?? 5} min per target, with the bank's test certificate where we have one. Many more samples than the audit's own calls; shown for context, not scored.`" />
      <CardContent>
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="border-b border-border text-left text-xs text-muted-foreground">
                <th class="py-2 font-medium">Target</th>
                <th class="px-2 text-right font-medium">Samples</th>
                <th class="px-2 text-right font-medium">p50 ms</th>
                <th class="px-2 text-right font-medium">p95 ms</th>
                <th class="px-2 font-medium">vs {{ th.latencyP95Ms }} ms ({{ th.source }})</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="m in monitorLatency" :key="m.id" class="border-b border-border last:border-0">
                <td class="py-2">{{ m.name }}</td>
                <td class="px-2 text-right tabular-nums">{{ m.samples }}</td>
                <td class="px-2 text-right tabular-nums">{{ m.p50 ?? '-' }}</td>
                <td class="px-2 text-right tabular-nums" :title="m.p95 === null ? 'Too few samples for a percentile' : ''">{{ m.p95 ?? `n<${th.latencyMinSamples}` }}</td>
                <td class="px-2 text-xs text-muted-foreground">{{ (m.p95 ?? m.p50 ?? 0) <= th.latencyP95Ms ? 'within' : 'above' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p class="mt-3 text-xs leading-relaxed text-muted-foreground">Measured from the auditor's server, each sample a new request including connection setup. Context for the per-endpoint timings below; the audit's verdicts do not use it.</p>
      </CardContent>
    </Card>

    <Card v-for="t in withStats" :key="t.id">
      <CardHeader :title="t.name" :description="DESC[accessOf(t)]" />
      <CardContent class="space-y-5">
        <LatencyChart :stats="t.endpointStats" :threshold="th.latencyP95Ms" :min-samples="th.latencyMinSamples" />
        <!-- Phones: one block per endpoint instead of a 9-column table. -->
        <ul class="divide-y divide-border border-t border-border md:hidden">
          <li v-for="s in t.endpointStats" :key="s.operation" class="py-2.5">
            <div class="flex items-center justify-between gap-2">
              <span class="min-w-0 truncate font-mono text-xs">{{ s.operation }}</span>
              <StatusBadge :status="ok(s) ? 'pass' : 'fail'" />
            </div>
            <div class="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 text-xs tabular-nums text-muted-foreground">
              <span>{{ s.samples }} calls</span>
              <span>{{ s.availabilityPct }}% available</span>
              <span>{{ s.errorRatePct }}% errors</span>
              <span v-if="s.serverP50 !== undefined && s.serverP50 !== null">server p50 {{ s.serverP50 }} ms</span>
            </div>
            <div class="mt-0.5 font-mono text-[11px] text-muted-foreground [overflow-wrap:anywhere]">{{ Object.entries(s.statuses).map(([k, v]) => `${k}×${v}`).join(' ') }}</div>
          </li>
        </ul>
        <div class="hidden overflow-x-auto md:block">
          <table class="w-full text-sm">
            <thead>
              <tr class="border-b border-border text-left text-xs text-muted-foreground">
                <th class="py-2 font-medium">Endpoint</th>
                <th class="px-2 text-right font-medium">Calls</th>
                <th class="px-2 text-right font-medium">Available</th>
                <th class="px-2 text-right font-medium">Errors</th>
                <th class="px-2 text-right font-medium">p50 ms</th>
                <th class="px-2 text-right font-medium">p95 ms</th>
                <th class="px-2 text-right font-medium">Server p50 ms</th>
                <th class="px-2 font-medium">Status codes</th>
                <th class="px-2 font-medium">Verdict</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="s in t.endpointStats" :key="s.operation" class="border-b border-border last:border-0">
                <td class="py-2 font-mono text-xs">{{ s.operation }}</td>
                <td class="px-2 text-right tabular-nums">{{ s.samples }}</td>
                <td class="px-2 text-right tabular-nums">{{ s.availabilityPct }}%</td>
                <td class="px-2 text-right tabular-nums">{{ s.errorRatePct }}%</td>
                <td class="px-2 text-right tabular-nums">{{ s.p50 }}</td>
                <td class="px-2 text-right tabular-nums" :title="s.samples < th.latencyMinSamples ? 'Too few samples for a percentile' : ''">{{ s.samples >= th.latencyMinSamples ? s.p95 : `n<${th.latencyMinSamples}` }}</td>
                <td class="px-2 text-right tabular-nums">{{ s.serverP50 ?? '-' }}</td>
                <td class="px-2 font-mono text-xs text-muted-foreground">{{ Object.entries(s.statuses).map(([k, v]) => `${k}×${v}`).join(' ') }}</td>
                <td class="px-2"><StatusBadge :status="ok(s) ? 'pass' : 'fail'" /></td>
              </tr>
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
    <Card v-for="t in noStats" :key="t.id">
      <CardHeader :title="t.name" :description="DESC[accessOf(t)]" />
      <CardContent>
        <div class="flex items-start gap-3 rounded-lg border border-dashed border-border p-4">
          <CircleSlash class="mt-0.5 size-5 shrink-0 text-muted-foreground" />
          <div class="min-w-0">
            <div class="text-sm font-medium">No performance data could be obtained for this bank in this run</div>
            <p class="mt-1 text-sm leading-relaxed text-muted-foreground [overflow-wrap:anywhere]">{{ accessOf(t) === 'spec' ? 'Only the published OpenAPI document is checked; the bank publishes no host to call.' : whyNoData(t) }}</p>
          </div>
        </div>
      </CardContent>
    </Card>
  </div>
</template>
