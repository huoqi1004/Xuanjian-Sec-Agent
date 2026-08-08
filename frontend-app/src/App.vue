<template>
  <router-view />
</template>

<script setup lang="ts">
import { onMounted, onUnmounted } from 'vue';
import { wsClient } from '@/utils/ws';
import { useUserStore } from '@/stores/user';

const userStore = useUserStore();

onMounted(() => {
  if (userStore.token) {
    wsClient.onStatusChange = (connected) => {
      userStore.wsConnected = connected;
    };
    wsClient.connect();
  }
});

onUnmounted(() => {
  wsClient.disconnect();
});
</script>
