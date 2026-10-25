<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue';
import Card from '@/components/ui/Card.vue';
import CardHeader from '@/components/ui/CardHeader.vue';
import CardContent from '@/components/ui/CardContent.vue';
import { fetchAlerts, RULE_LABEL, tbilisiTime, type AlertsResponse } from '@/lib/alerts';

// Last 50 Telegram/email alerts sent by the backend. Refreshed every minute, like the alert rules.
const data = ref<AlertsResponse | null>(null);
const error = ref('');
let timer: ReturnType<typeof setInterval> | undefined;

async function load() {
  try {
    data.value = await fetchAlerts();
    error.value = '';
  } catch (e: any) {
    error.value = e.message;
  }
}
onMounted(() => {
  load();
  timer = setInterval(load, 60_000);
});
onUnmounted(() => clearInterval(timer));

const ruleClass = (rule: string) =>
  rule === 'down' || rule === 'new-high-findings'
    ? 'text-[var(--status-critical)]'
    : rule === 'recovered' || rule === 'latency-ok'
      ? 'text-[var(--status-good)]'
      : rule === 'audit-finished'
        ? 'text-muted-foreground'
        : 'text-[var(--status-serious)]';

/** The message without its first line (the title repeats bank and rule). */
const body = (m: string) => m.split('\n').slice(1).join('\n');
</script>

<template>
  <Card>
    <CardHeader
      title="Alerts"
      :description="
        data
          ? data.enabled
            ? `Sent to ${data.channels.join(' and ')}. Times in Tbilisi.`
            : 'Alerting is off (no channel configured or ALERTS_ENABLED=false). Times in Tbilisi.'
          : 'Times in Tbilisi.'
      "
    />
    <CardContent>
      <p v-if="error" class="text-sm text-[var(--status-critical)]">Could not load alerts: {{ error }}</p>
      <p v-else-if="data && !data.alerts.length" class="text-sm text-muted-foreground">No alerts yet.</p>
      <ul v-else-if="data" class="divide-y divide-border">
        <li v-for="(a, i) in data.alerts" :key="i" class="flex flex-col gap-1 py-2.5 text-sm">
          <div class="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
            <span :class="['font-medium', ruleClass(a.rule)]">{{ RULE_LABEL[a.rule] ?? a.rule }}</span>
            <span v-if="a.bank" class="font-medium">{{ a.bank }}</span>
            <span class="text-xs text-muted-foreground">{{ tbilisiTime(a.ts) }}</span>
            <span v-if="!a.ok" class="text-xs text-[var(--status-critical)]">not delivered</span>
          </div>
          <p class="whitespace-pre-line break-words text-xs text-muted-foreground">{{ body(a.message) }}</p>
        </li>
      </ul>
    </CardContent>
  </Card>
</template>
