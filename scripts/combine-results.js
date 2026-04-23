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
        javaResults = JSON.parse(fs.readFileSync('results.json', 'utf-8'));
    }

    const mapping = JSON.parse(fs.readFileSync('config/stride-attacks-map.json', 'utf-8'));

    const combinedThreats = [];
    const summary = {
        detected: 0,
        confirmed: 0,
        unconfirmed: 0,
        unavailable: false
    };

    // Process AI Threats
    for (const category in aiOutput.threats) {
        aiOutput.threats[category].forEach(threat => {
            summary.detected++;
            const categoryMapping = mapping[category] || [];
            
            // Check if any mapped Java attack confirmed this threat
            const confirmation = javaResults.find(res => 
                categoryMapping.includes(res.attack_class.replace('Attack', '')) && res.vulnerable === true
            );

            const combinedThreat = {
                ...threat,
                category: category,
                confirmed: confirmation ? true : (javaResults.length > 0 ? false : null),
                dynamic_evidence: confirmation ? {
                    attack: confirmation.attack_name,
                    evidence: confirmation.evidence,
                    response_code: confirmation.response_code
                } : null
            };

            if (combinedThreat.confirmed === true) summary.confirmed++;
            else if (combinedThreat.confirmed === false) summary.unconfirmed++;

            combinedThreats.push(combinedThreat);
        });
    }

    const report = {
        timestamp: new Date().toISOString(),
        executive_summary: {
            total_detected: summary.detected,
            total_confirmed: summary.confirmed,
            total_unconfirmed: summary.unconfirmed,
            system_status: javaResults.length > 0 ? "available" : "unavailable_or_skipped"
        },
        stride_analysis: aiOutput.threats,
        dynamic_validation: javaResults,
        combined_threats: combinedThreats
    };

    fs.writeFileSync('combined-report.json', JSON.stringify(report, null, 2));
    console.log("✅ Reporte combinado generado: combined-report.json");
}

run();
