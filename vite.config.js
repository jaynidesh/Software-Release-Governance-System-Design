import { defineConfig } from 'vite';
import laravel from 'laravel-vite-plugin';

export default defineConfig({
    plugins: [
        laravel({
            input: ['resources/sass/app.scss', 'resources/js/app.js'],
            refresh: true,
        }),
    ],
    server: {
        origin: process.env.VITE_DEV_SERVER_ORIGIN ?? 'http://localhost:5173',
        watch: {
            ignored: ['**/storage/framework/views/**'],
        },
    },
});
