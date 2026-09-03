import { defineConfig, loadEnv } from 'vite';
import laravel from 'laravel-vite-plugin';

export default defineConfig(({ mode }) => {
    const viteEnvironment = loadEnv(mode, process.cwd(), '');

    return {
        plugins: [
            laravel({
                input: ['resources/sass/app.scss', 'resources/js/app.js'],
                refresh: true,
            }),
        ],
        server: {
            origin: viteEnvironment.VITE_DEV_SERVER_ORIGIN ?? 'http://localhost:5173',
            watch: {
                ignored: ['**/storage/framework/views/**'],
            },
        },
    };
});
