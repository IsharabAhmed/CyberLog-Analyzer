
document.addEventListener('DOMContentLoaded', () => {
    // Basic chart initialization for demo
    fetch('/dashboard/api/severity-distribution/')
        .then(res => res.json())
        .then(data => {
            const ctx = document.getElementById('severity-chart');
            if (ctx) {
                new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: data.labels,
                        datasets: [{ data: data.data, backgroundColor: data.colors }]
                    },
                    options: { responsive: true, maintainAspectRatio: false }
                });
            }
        }).catch(e => console.error(e));
});
