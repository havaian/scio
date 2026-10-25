<script setup lang="ts">
import { ref } from 'vue';
import { ChevronDown, Wrench, Sparkles } from 'lucide-vue-next';
import StatusBadge from '@/components/ui/StatusBadge.vue';
import StandardRefs from '@/components/StandardRefs.vue';
import FindingCalls from '@/components/FindingCalls.vue';
import type { Finding } from '@/lib/api';
import { LAYER_LABEL } from '@/lib/utils';

defineProps<{ f: Finding; targetName?: string }>();
const open = ref(false);
const label = (s: string) => s.replace(/_/g, ' ');
const gateText = { auto: 'confident', review: 'needs review', human: 'human decision' } as const;
</script>

<template>
  <div class="rounded-lg border border-border bg-card p-3">
    <button class="flex w-full items-start gap-3 text-left" :aria-expanded="open" @click="open = !open">
      <!-- Small screens: badge sits above the title so the text keeps the full width. -->
      <div class="hidden shrink-0 sm:block"><StatusBadge :status="f.status" :severity="f.severity" /></div>
      <div class="min-w-0 flex-1">
        <div class="mb-1.5 sm:hidden"><StatusBadge :status="f.status" :severity="f.severity" /></div>
        <div class="text-sm font-medium">{{ f.title }}<span v-if="f.source === 'ai'" class="ml-2 rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground">AI-generated · not scored</span></div>
        <div class="mt-0.5 text-xs text-muted-foreground [overflow-wrap:anywhere]">
          {{ targetName ?? f.targetId }} · {{ LAYER_LABEL[f.layer] }}<template v-if="f.endpoint"> · <span class="font-mono">{{ f.endpoint }}</span></template>
        </div>
        <p class="mt-1.5 text-sm leading-relaxed [overflow-wrap:anywhere]">{{ f.message }}</p>
        <div v-if="f.ai" class="mt-2 flex w-fit max-w-full flex-wrap items-center gap-1.5 rounded-md border border-dashed border-border px-2 py-1 text-xs text-muted-foreground">
          <Sparkles class="size-3.5" />
          <span>AI triage: <b class="text-foreground">{{ label(f.ai.impact) }}</b> ({{ Math.round(f.ai.impactConfidence * 100) }}%) · fix in <b class="text-foreground">{{ label(f.ai.owner) }}</b></span>
          <span class="rounded bg-muted px-1">{{ gateText[f.ai.gate] }}</span>
          <span v-if="!f.ai.agreesWithRules" class="rounded bg-muted px-1">disagrees with rules: AI says {{ f.ai.aiSeverity }}, rules say {{ f.severity }}</span>
        </div>
      </div>
      <ChevronDown class="mt-1 size-4 shrink-0 text-muted-foreground transition-transform" :class="open && 'rotate-180'" />
    </button>
    <div v-if="open" class="mt-3 space-y-2 border-t border-border pt-3 text-sm">
      <div v-if="f.expected || f.actual" class="grid gap-1 rounded-md bg-muted p-2 font-mono text-xs">
        <div class="[overflow-wrap:anywhere]"><span class="text-muted-foreground">expected </span>{{ f.expected ?? '-' }}</div>
        <div class="break-all"><span class="text-muted-foreground">actual&nbsp;&nbsp;&nbsp;</span>{{ f.actual ?? '-' }}</div>
      </div>
      <div v-if="f.fix" class="flex gap-2"><Wrench class="mt-0.5 size-4 shrink-0 text-muted-foreground" /><div class="min-w-0 [overflow-wrap:anywhere]"><span class="font-medium">Fix: </span>{{ f.fix }}</div></div>
      <StandardRefs :standard="f.standard" />
      <details v-if="f.evidence" class="text-xs">
        <summary class="cursor-pointer text-muted-foreground">Evidence</summary>
        <pre class="mt-1 max-h-64 overflow-auto rounded-md bg-muted p-2">{{ JSON.stringify(f.evidence, null, 2) }}</pre>
      </details>
      <FindingCalls :f="f" />
      <div class="flex items-center gap-1.5 text-[11px] text-muted-foreground"><span>Check ID</span><code class="rounded bg-muted px-1.5 py-0.5 font-mono text-foreground">{{ f.checkId }}</code></div>
    </div>
  </div>
</template>
