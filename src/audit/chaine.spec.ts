import { describe, it, expect } from '@jest/globals';
import { sql } from 'kysely';
import { AuditService } from './audit-service.js';
import {
  installerBancAudit,
  admin,
  runtime,
  T_A,
  mkDb,
  DB,
  CREDENTIALS,
} from '../fixtures/audit-banc.js';
installerBancAudit('tenancy_chaine_test');

describe('chaîne : écrite par qui n’a PAS audit.read', () => {
  it('le second maillon est chaîné au premier', async () => {
    // MESURÉ avant correction : empreinte_precedente NULL pour les deux.
    await runtime.transaction().execute(async (trx) => {
      await sql`select set_config('app.tenant', ${T_A}, true)`.execute(trx);
      const s = new AuditService(trx);
      await s.record({
        tenantId: T_A,
        acteurRole: 'x',
        action: 'chaine.un',
        cibleType: 't',
      });
      await s.record({
        tenantId: T_A,
        acteurRole: 'x',
        action: 'chaine.deux',
        cibleType: 't',
      });
    });
    const r = await sql<{ action: string; prec: boolean }>`
      select action, empreinte_precedente is not null as prec from journal_audit
      where action like 'chaine.%' order by id`.execute(admin);
    expect(r.rows).toEqual([
      { action: 'chaine.un', prec: false },
      { action: 'chaine.deux', prec: true },
    ]);
    expect((await new AuditService(admin).verifyChain(T_A)).valid).toBe(true);
  });
});

describe('chaîne : 20 écritures CONCURRENTES', () => {
  it('ne fourche pas', async () => {
    // 20 connexions réelles : avec `runtime` (max 2), la concurrence serait
    // trop faible pour révéler une fourche.
    const large = mkDb(DB, 'app_runtime', CREDENTIALS.runtime, 20);
    try {
      await Promise.all(
        Array.from({ length: 20 }, (_, i) =>
          large.transaction().execute(async (trx) => {
            await sql`select set_config('app.tenant', ${T_A}, true)`.execute(trx);
            await new AuditService(trx).record({
              tenantId: T_A,
              acteurRole: 'x',
              action: `concurrent.${i}`,
              cibleType: 't',
            });
          }),
        ),
      );
    } finally {
      await large.destroy();
    }
    const v = await new AuditService(admin).verifyChain(T_A);
    expect(v).toEqual({ valid: true, checked: 20 });
  });
});

describe('chaîne : le contenu ENTIER est couvert', () => {
  async function falsifier(requete: ReturnType<typeof sql>) {
    await sql`drop rule journal_no_update on journal_audit`.execute(admin);
    try {
      await requete.execute(admin);
    } finally {
      await sql`create rule journal_no_update as on update to journal_audit do instead nothing`.execute(
        admin,
      );
    }
  }

  it('un MOTIF réécrit en base est détecté', async () => {
    await new AuditService(admin).record({
      tenantId: T_A,
      acteurRole: 'x',
      action: 'participant.reject',
      cibleType: 'participant',
      motif: 'Dossier incomplet',
    });
    await falsifier(sql`update journal_audit set motif = 'Motif arrangé après coup'`);
    expect((await new AuditService(admin).verifyChain(T_A)).valid).toBe(false);
  });

  it('un « après » réécrit en base est détecté', async () => {
    await new AuditService(admin).record({
      tenantId: T_A,
      acteurRole: 'x',
      action: 'tenant.update',
      cibleType: 'tenant',
      apres: { nom: 'Vrai' },
    });
    await falsifier(sql`update journal_audit set apres = '{"nom":"Faux"}'::jsonb`);
    expect((await new AuditService(admin).verifyChain(T_A)).valid).toBe(false);
  });

  it('le RÔLE figé réécrit en base est détecté', async () => {
    await new AuditService(admin).record({
      tenantId: T_A,
      acteurRole: 'observateur',
      action: 'x.y',
      cibleType: 't',
    });
    await falsifier(sql`update journal_audit set acteur_role = 'proprietaire'`);
    expect((await new AuditService(admin).verifyChain(T_A)).valid).toBe(false);
  });
});

describe('chaîne : indépendante du fuseau de la session', () => {
  it('écrite en UTC, vérifiée depuis Asia/Tokyo : VALIDE', async () => {
    // Trouvé en revue : `horodatage::text` dépend du paramètre TimeZone. Une
    // vérification depuis un autre fuseau concluait à une falsification.
    await admin.transaction().execute(async (trx) => {
      await sql`set local timezone = 'UTC'`.execute(trx);
      const s = new AuditService(trx);
      await s.record({
        tenantId: T_A,
        acteurRole: 'x',
        action: 'fuseau.un',
        cibleType: 't',
      });
      await s.record({
        tenantId: T_A,
        acteurRole: 'x',
        action: 'fuseau.deux',
        cibleType: 't',
      });
    });
    const v = await admin.transaction().execute(async (trx) => {
      await sql`set local timezone = 'Asia/Tokyo'`.execute(trx);
      return new AuditService(trx).verifyChain(T_A);
    });
    expect(v).toEqual({ valid: true, checked: 2 });
  });
});
