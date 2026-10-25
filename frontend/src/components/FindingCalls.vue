<script setup lang="ts">
import { ref } from 'vue';
import { ExternalLink, FileText } from 'lucide-vue-next';
import { api, type Exchange, type Finding } from '@/lib/api';
import { store } from '@/lib/store';

// Shows the raw requests behind a finding (from the stored exchange log), so every verdict can be traced.
const props = defineProps<{ f: Finding }>();
const calls = ref<Exchange[] | null>(null);
const loading = ref(false);
const error = ref('');

/** Exchange operation names recorded for each check (most checks use their own id). */
const OPS: Record<string, string[]> = {
  // Mock full flow and bank sandbox journey (sandbox.*, sca.* prefixes also match sca.browser, sca.browser.dump, ...).
  'flow.consent': ['consent.create', 'sandbox.consent'],
  'flow.authorize': ['oauth.authorize', 'sca.approve', 'oauth.token', 'sandbox.authorisation', 'sandbox.oauth-metadata', 'sca', 'sandbox.token'],
  'flow.token': ['oauth.token', 'sandbox.token'],
  'flow.oauth-scope': ['sca'],
  'flow.consent-valid': ['sandbox.consent-status'],
  'flow.oauth-prestep': ['sandbox.consent-prestep', 'sandbox.consent-status'],
  'flow.detailed-consent': ['sandbox.consent-detailed', 'sandbox.authorisation', 'sandbox.oauth-metadata', 'sca', 'sandbox.token', 'ais.balances', 'ais.transactions'],
  'flow.sandbox': ['sandbox', 'sca', 'ais'],
  'live.redirect-uri-header': ['sandbox.consent', 'sandbox.authorisation'],
  'live.consent-links': ['sandbox.consent'],
  'spec.consent-example': ['sandbox.consent'],
  'sec.jws-typ-required': ['sandbox.consent'],
  'sec.jws-request-target': ['sandbox.consent'],
  'sec.code-replay': ['neg.code-replay'],
  'sec.pkce-enforced': ['neg.pkce-wrong-verifier'],
  'sec.redirect-binding': ['neg.redirect-mismatch'],
  'sec.message-signing': ['neg.unsigned'],
  'live.consent-delete': ['neg.consent-delete', 'consent.delete', 'consent.status.after-delete'],
  'live.booking-status': ['live.booking-status'],
  'live.with-balance': ['ais.accounts', 'live.without-balance'],
  'pis.create-response': ['pis.create'],
  'pis.authorize': ['pis.oauth'],
  'pis.echo': ['pis.details'],
  'pis.cancel': ['pis.cancel'],
  'pis.recurring': ['pis.recurring.create'],
  'pis.recurring-response': ['pis.recurring.create'],
  'pis.deferred': ['pis.deferred.create'],
  'pis.deferred-response': ['pis.deferred.create'],
  'v2.consent': ['v2.consent.create'],
  'v2.authorize': ['v2.oauth'],
  'v2.consent-status': ['v2.consent.status'],
  'v2.consent-delete': ['v2.consent.delete', 'v2.consent.after-delete'],
  'v2.path-as-documented': ['v2.loans.balances', 'v2.savings.balances'],
  'rel.flow-outage': ['consent.create'],
};

/** Checks read from the bank's published OpenAPI document: no API call involved. */
const fromSpec = props.f.checkId.startsWith('spec.');
const specSource = store.report?.targets.find((t) => t.id === props.f.targetId)?.source;

function operations(): string[] {
  const f = props.f;
  // Sandbox journey timing: all calls of the journey.
  if ((f.checkId === 'rel.availability' || f.checkId === 'lat.p95') && f.endpoint?.startsWith('sandbox journey')) return ['sandbox', 'ais'];
  if (OPS[f.checkId]) return OPS[f.checkId];
  if ((f.checkId === 'rel.availability' || f.checkId === 'lat.p95') && f.endpoint)
    return [f.endpoint.startsWith('front door') ? 'probe.front-door' : `probe.${f.endpoint}`];
  return [f.checkId];
}

async function load() {
  if (!store.report) return;
  loading.value = true;
  error.value = '';
  try {
    calls.value = (await api.exchanges(store.report.run.id, props.f.targetId, operations())).slice(0, 20);
  } catch (e: any) {
    error.value = e.message;
  } finally {
    loading.value = false;
  }
}
</script>

<template>
  <div class="text-xs">
    <div v-if="fromSpec" class="flex flex-wrap items-center gap-2 rounded-md border border-dashed border-border px-2.5 py-2">
      <FileText class="size-4 shrink-0 text-muted-foreground" />
      <span class="text-muted-foreground">Derived from the bank's published OpenAPI document. No API calls involved.</span>
      <a v-if="specSource" :href="specSource" target="_blank" rel="noopener" class="ml-auto inline-flex items-center gap-1 rounded-md border border-border bg-background px-2 py-1 font-medium text-foreground hover:bg-accent" @click.stop>
        Spec source <ExternalLink class="size-3.5" />
      </a>
    </div>
    <button v-else-if="calls === null" class="text-muted-foreground underline underline-offset-2 hover:text-foreground" :disabled="loading" @click.stop="load">
      {{ loading ? 'Loading calls…' : 'Show the calls behind this result' }}
    </button>
    <p v-else-if="error" class="text-muted-foreground">{{ error }}</p>
    <p v-else-if="!calls.length" class="text-muted-foreground">No recorded calls for this check (it is derived from the spec or from several calls).</p>
    <div v-else class="space-y-1.5">
      <div class="text-muted-foreground">Calls behind this result ({{ calls.length }}{{ calls.length === 20 ? '+' : '' }})</div>
      <details v-for="(c, i) in calls" :key="i" class="rounded-md border border-border">
        <summary class="cursor-pointer px-2 py-1.5 font-mono [overflow-wrap:anywhere]">
          {{ c.method }} {{ c.url.replace(/^https?:\/\/[^/]+/, '') }} → <b>{{ c.status || c.error }}</b> · {{ Math.round(c.durationMs) }} ms
        </summary>
        <div class="space-y-1 border-t border-border p-2 font-mono">
          <div><span class="text-muted-foreground">operation</span> {{ c.operation }} · <span class="text-muted-foreground">X-Request-ID</span> {{ c.requestHeaders['X-Request-ID'] ?? '-' }}</div>
          <div class="text-muted-foreground">request headers</div>
          <pre class="max-h-40 overflow-auto rounded bg-muted p-1.5">{{ JSON.stringify(c.requestHeaders, null, 2) }}</pre>
          <div class="text-muted-foreground">response headers</div>
          <pre class="max-h-40 overflow-auto rounded bg-muted p-1.5">{{ JSON.stringify(c.responseHeaders, null, 2) }}</pre>
          <div class="text-muted-foreground">response body (shortened, tokens redacted)</div>
          <pre class="max-h-56 overflow-auto whitespace-pre-wrap break-all rounded bg-muted p-1.5">{{ c.bodySnippet }}</pre>
        </div>
      </details>
    </div>
  </div>
</template>
