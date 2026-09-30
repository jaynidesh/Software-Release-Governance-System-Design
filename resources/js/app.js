import * as bootstrap from 'bootstrap';

window.bootstrap = bootstrap;

document.querySelectorAll('[data-otp-resend]').forEach((form) => {
    const button = form.querySelector('[data-otp-resend-button]');
    const feedback = form.querySelector('[data-otp-resend-feedback]');
    const availableAt = Number(form.dataset.resendAvailableAt);

    if (!(button instanceof HTMLButtonElement) || !(feedback instanceof HTMLElement) || !Number.isFinite(availableAt) || availableAt <= 0) {
        return;
    }

    const updateCountdown = () => {
        const seconds = Math.max(0, Math.ceil((availableAt - Date.now()) / 1000));
        button.disabled = seconds > 0;
        feedback.textContent = seconds > 0
            ? `You can request another code in ${seconds} second${seconds === 1 ? '' : 's'}.`
            : 'You can request another code now.';

        return seconds;
    };

    if (updateCountdown() > 0) {
        const timer = window.setInterval(() => {
            if (updateCountdown() === 0) {
                window.clearInterval(timer);
            }
        }, 1000);
    }
});
