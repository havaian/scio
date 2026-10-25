<script setup lang="ts">
import { computed } from 'vue';
import { CheckCircle2, XCircle, AlertTriangle, Info, MinusCircle } from 'lucide-vue-next';

// Status never relies on color alone: icon + label + color.
const props = defineProps<{ status: string; severity?: string; compact?: boolean }>();
const conf = computed(() => {
  switch (props.status) {
    case 'pass': return { icon: CheckCircle2, label: 'Pass', color: 'var(--status-good)' };
    case 'fail': return { icon: XCircle, label: props.severity && props.severity !== 'none' ? `Fail · ${props.severity}` : 'Fail', color: 'var(--status-critical)' };
    case 'warn': return { icon: AlertTriangle, label: 'Warn', color: 'var(--status-serious)' };
    case 'info': return { icon: Info, label: 'Info', color: 'var(--muted-foreground)' };
    default: return { icon: MinusCircle, label: 'Skip', color: 'var(--muted-foreground)' };
  }
});
</script>
<template>
  <span class="inline-flex items-center gap-1 whitespace-nowrap rounded-md border border-border px-1.5 py-0.5 text-[11px] font-medium" :title="conf.label">
    <component :is="conf.icon" class="size-3.5 shrink-0" :style="{ color: conf.color }" />
    <span v-if="!compact" class="text-foreground">{{ conf.label }}</span>
  </span>
</template>
