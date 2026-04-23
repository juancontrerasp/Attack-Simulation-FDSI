const fs = require('fs');

function run() {
    console.log("📊 Combinando resultados de análisis...");

    if (!fs.existsSync('threats-output.json')) {
        console.error("❌ Error: threats-output.json no encontrado.");
        process.exit(1);
    }

    const aiOutput = JSON.parse(fs.readFileSync('threats-output.json', 'utf-8'));
    let javaResults = [];
    if (fs.existsSync('results.json')) {
        try {
            javaResults = JSON.parse(fs.readFileSync('results.json', 'utf-8'));
        } catch (e) {
            console.warn("⚠️ Advertencia: results.json no es un JSON válido o está vacío.");
        }
    }

    const mapping = JSON.parse(fs.readFileSync('config/stride-attacks-map.json', 'utf-8'));

    const combinedThreats = [];
    const stats = {
        detected: 0,
        confirmed: 0,
        unconfirmed: 0,
    };

    // Process AI Threats
    for (const category in aiOutput.threats) {
        aiOutput.threats[category].forEach(threat => {
            stats.detected++;
            const categoryMapping = mapping[category] || [];
            
            // Filter results related to this category
            const relatedResults = javaResults.filter(res => 
                categoryMapping.includes(res.attack_class.replace('Attack', ''))
            );

            // Logic for confirmation
            const confirmation = relatedResults.find(res => res.vulnerable === true);
            const negativeConfirmation = relatedResults.find(res => res.vulnerable === false);

            let confirmedStatus = null;
            let reason = null;
            let dynamicEvidence = null;

            if (javaResults.length === 0) {
                confirmedStatus = null;
                reason = "system_unavailable_or_skipped";
            } else if (confirmation) {
                confirmedStatus = true;
                stats.confirmed++;
                dynamicEvidence = {
                    attack: confirmation.attack_name,
                    evidence: confirmation.evidence,
                    response_code: confirmation.response_code
                };
            } else if (negativeConfirmation) {
                confirmedStatus = false;
                stats.unconfirmed++;
                reason = "dynamic_test_passed_system_not_vulnerable";
            } else {
                confirmedStatus = null;
                reason = "no_dynamic_attack_mapped_or_executed";
            }

            combinedThreats.push({
                ...threat,
                category: category,
                confirmed: confirmedStatus,
                confirmation_reason: reason,
                dynamic_validation: dynamicEvidence
            });
        });
    }

    // Calculate Rate
    const rate = stats.detected > 0 ? (stats.confirmed / stats.detected) * 100 : 0;

    const report = {
        timestamp: new Date().toISOString(),
        executive_summary: {
            total_detected: stats.detected,
            total_confirmed: stats.confirmed,
            total_unconfirmed: stats.unconfirmed,
            confirmation_rate_percent: parseFloat(rate.toFixed(2)),
            system_status: javaResults.length > 0 ? "available" : "unavailable_or_skipped"
        },
        stride_analysis: aiOutput.threats,
        dynamic_validation: javaResults,
        combined_threats: combinedThreats
    };

    fs.writeFileSync('combined-report.json', JSON.stringify(report, null, 2));
    console.log(`✅ Reporte consolidado generado con éxito.`);
    console.log(`📈 Tasa de confirmación dinámica: ${rate.toFixed(2)}%`);
}

run();
