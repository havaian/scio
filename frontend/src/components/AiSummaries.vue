<script setup lang="ts">
import { computed } from 'vue';
import { Cpu, ShieldAlert, ShieldCheck } from 'lucide-vue-next';
import Card from '@/components/ui/Card.vue';
import CardHeader from '@/components/ui/CardHeader.vue';
import CardContent from '@/components/ui/CardContent.vue';
import type { Report } from '@/lib/api';

const props = defineProps<{ r: Report; bank?: string }>();
const list = computed(() => (props.r.local?.summaries ?? []).filter((s) => !props.bank || props.bank === 'all' || s.targetId === props.bank));
const names = computed(() => Object.fromEntries(props.r.targets.map((t) => [t.id, t.name])));
</script>

<template>
  <Card v-if="list.length">
    <CardHeader title="Plain-language summaries" description="Written on this machine by Qwen3 1.7B (QVAC) from computed findings only. Code checks every number against the data and rejects problem claims about layers that scored well." />
    <CardContent class="grid gap-3 md:grid-cols-2">
      <div v-for="s in list" :key="s.targetId" class="rounded-lg border border-border p-4">
        <div class="mb-1 flex items-center gap-2 text-xs text-muted-foreground">
          <Cpu class="size-3.5" />{{ names[s.targetId] ?? s.targetId }}
          <span class="ml-auto inline-flex items-center gap-1 rounded border border-border px-1.5 py-0.5">
            <ShieldCheck v-if="s.verified" class="size-3.5" style="color: var(--status-good)" />
            <ShieldAlert v-else class="size-3.5" style="color: var(--status-serious)" />
            {{ s.verified ? 'checked against data' : 'needs review' }}
          </span>
        </div>
        <div class="font-medium">{{ s.headline }}</div>
        <p class="mt-1 text-sm">{{ s.summary }}</p>
        <ul class="mt-2 list-disc space-y-0.5 pl-5 text-sm">
          <li v-for="a in s.actions" :key="a">{{ a }}</li>
        </ul>
        <p v-if="!s.verified" class="mt-2 text-xs text-muted-foreground">Guardrail: {{ s.issues.join('; ') }}</p>
      </div>
    </CardContent>
  </Card>
</template>
