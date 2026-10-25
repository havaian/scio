<script setup lang="ts">
import { computed } from 'vue';
import { CheckCircle2, XCircle, Loader2, Eye } from 'lucide-vue-next';
import Button from '@/components/ui/Button.vue';
import { loadReport, store } from '@/lib/store';
import { fmtTime } from '@/lib/utils';

function open(id: string) {
  store.selectedRun = id;
  loadReport(id);
}

// One card per run: status, time, duration, and the targets it covered as chips (names from the report on screen).
const names = computed<Record<string, string>>(() => Object.fromEntries((store.report?.targets ?? []).map((t) => [t.id, t.name])));
const STATUS = {
  done: { icon: CheckCircle2, label: 'Done', color: 'var(--status-good)' },
  failed: { icon: XCircle, label: 'Failed', color: 'var(--status-critical)' },
  running: { icon: Loader2, label: 'Running', color: 'var(--status-warning)' },
} as const;
function duration(a?: string, b?: string) {
  if (!a || !b) return '';
  const s = Math.round((new Date(b).getTime() - new Date(a).getTime()) / 1000);
  return s >= 60 ? `${Math.floor(s / 60)} min ${s % 60} s` : `${s} s`;
}
</script>

<template>
  <div class="space-y-4">
    <div>
      <h2 class="text-sm font-semibold">Audit runs</h2>
      <p class="text-xs text-muted-foreground">Every run is stored with its findings and the raw request/response log. Newest first.</p>
    </div>

    <div class="grid grid-cols-1 gap-3">
      <article
        v-for="(run, i) in store.runs"
        :key="run.id"
        class="min-w-0 rounded-xl border bg-card p-4 transition-colors"
        :class="store.report?.run.id === run.id ? 'border-foreground/30' : 'border-border'"
      >
        <div class="flex flex-wrap items-center gap-x-3 gap-y-2">
          <span class="inline-flex items-center gap-1.5 rounded-full border border-border px-2 py-0.5 text-xs font-medium" :style="{ color: STATUS[run.status].color }">
            <component :is="STATUS[run.status].icon" class="size-3.5" :class="run.status === 'running' && 'animate-spin'" />
            {{ STATUS[run.status].label }}
          </span>
          <span v-if="i === 0" class="rounded-full bg-muted px-2 py-0.5 text-[11px] font-medium text-muted-foreground">Latest</span>
          <span class="text-sm font-medium">{{ fmtTime(run.startedAt) }}</span>
          <span v-if="duration(run.startedAt, run.finishedAt)" class="text-xs text-muted-foreground">· {{ duration(run.startedAt, run.finishedAt) }}</span>
          <div class="ml-auto">
            <span v-if="store.report?.run.id === run.id" class="inline-flex items-center gap-1 text-xs text-muted-foreground"><Eye class="size-3.5" />Viewing</span>
            <Button v-else-if="run.status === 'done'" size="sm" variant="outline" @click="open(run.id)">Open</Button>
          </div>
        </div>
        <div class="mt-1 font-mono text-[11px] text-muted-foreground [overflow-wrap:anywhere]">{{ run.id }}</div>
        <p v-if="run.error" class="mt-2 text-xs text-[var(--status-critical)]">{{ run.error }}</p>
        <div class="mt-3 flex flex-wrap items-center gap-1.5">
          <span class="text-xs text-muted-foreground">{{ run.targets.length }} target{{ run.targets.length === 1 ? '' : 's' }}:</span>
          <span v-for="t in run.targets" :key="t" class="rounded-md border border-border bg-muted/50 px-1.5 py-0.5 text-[11px]">{{ names[t] ?? t }}</span>
        </div>
      </article>
      <p v-if="!store.runs.length" class="py-8 text-center text-sm text-muted-foreground">No runs yet.</p>
    </div>
  </div>
</template>
