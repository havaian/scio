<script setup lang="ts">
import { computed } from 'vue';
import { Network } from 'lucide-vue-next';
import Card from '@/components/ui/Card.vue';
import CardHeader from '@/components/ui/CardHeader.vue';
import CardContent from '@/components/ui/CardContent.vue';
import type { Report } from '@/lib/api';

const props = defineProps<{ r: Report }>();
const names = computed(() => Object.fromEntries(props.r.targets.map((t) => [t.id, t.name])));
</script>

<template>
  <Card v-if="r.local?.clusters">
    <CardHeader title="Shared root causes" :description="`Findings grouped by meaning with ${r.local.clusters.model.replace(' (local)', '')} via QVAC, on this machine, cosine similarity ≥ ${r.local.clusters.threshold}. One fix closes the whole group.`" />
    <CardContent class="grid gap-3">
      <div v-for="c in r.local.clusters.clusters" :key="c.label" class="rounded-lg border border-border p-3">
        <div class="flex flex-wrap items-center gap-2 text-sm">
          <Network class="size-4 text-muted-foreground" />
          <span class="font-medium">{{ c.label }}</span>
          <span class="text-xs text-muted-foreground">{{ c.size }} findings · {{ c.checks.length }} {{ c.checks.length === 1 ? 'check' : 'checks' }} · {{ c.targets.map((t) => names[t] ?? t).join(', ') }} · cohesion {{ c.cohesion }}</span>
        </div>
        <ul class="mt-2 grid gap-1 text-xs">
          <li v-for="(m, i) in c.members" :key="i" class="flex gap-2">
            <span class="text-muted-foreground">{{ names[m.targetId] ?? m.targetId }}</span>
            <span>{{ m.title }}</span>
            <span v-if="m.endpoint" class="font-mono text-muted-foreground">{{ m.endpoint }}</span>
          </li>
        </ul>
      </div>
      <p v-if="!r.local.clusters.clusters.length" class="text-sm text-muted-foreground">No groups above the similarity threshold in this run.</p>
    </CardContent>
  </Card>
</template>
