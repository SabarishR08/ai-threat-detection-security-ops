// Injected into suspicious tabs to show a warning overlay
(function() {
    if (window.__phishWarningInjected) return;
    window.__phishWarningInjected = true;
    function injectWarning() {
        if (!document.body) {
            setTimeout(injectWarning, 50);
            return;
        }
        console.log('[PhishWarning] Injecting warning overlay');
        const overlay = document.createElement('div');
        overlay.id = 'phish-warning-overlay';
        overlay.style = `
            position: fixed; z-index: 999999; top: 0; left: 0; width: 100vw; height: 100vh;
            background: rgba(20,0,40,0.97); color: #fff; display: flex; flex-direction: column;
            align-items: center; justify-content: center; font-family: 'Outfit', Arial, sans-serif;
        `;
        overlay.innerHTML = `
            <div style="background: #1a0033; border: 2px solid #ff3131; border-radius: 18px; padding: 36px 32px; box-shadow: 0 0 32px #ff3131; max-width: 420px; text-align: center;">
                <h2 style="color: #ff3131; font-size: 2rem; margin-bottom: 12px;">⚠️ Suspicious Link Blocked</h2>
                <p style="margin-bottom: 18px; font-size: 1.1rem;">This site was flagged as <b>phishing or malicious</b>.<br>For your safety, access is blocked.</p>
                <div style="margin-bottom: 18px;">
                    <button id="phish-go-back" style="background: #ff3131; color: #fff; border: none; border-radius: 8px; padding: 10px 24px; font-size: 1rem; margin-right: 10px; cursor: pointer;">Go Back</button>
                    <button id="phish-proceed" style="background: #222; color: #ff3131; border: 1px solid #ff3131; border-radius: 8px; padding: 10px 24px; font-size: 1rem; cursor: pointer;">Proceed Anyway</button>
                </div>
                <div style="font-size: 0.9rem; color: #ffb800;">If you believe this is a mistake, proceed with caution.</div>
            </div>
        `;
        document.body.appendChild(overlay);
        document.body.style.overflow = 'hidden';
        document.getElementById('phish-go-back').onclick = function() {
            window.close();
            window.location.href = 'about:blank';
        };
        document.getElementById('phish-proceed').onclick = function() {
            overlay.remove();
            document.body.style.overflow = '';
        };
    }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', injectWarning);
    } else {
        injectWarning();
    }
})();
