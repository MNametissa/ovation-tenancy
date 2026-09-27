import { describe, it, expect } from '@jest/globals';
import { sql } from 'kysely';
import { AuditService } from './audit-service.js';
import {
  installerBancAudit,
  admin,
  T_A,
  U_1,
  mkLogger,
} from '../fixtures/audit-banc.js';
installerBancAudit('tenancy_audit_test');

describe('T3.8 — journal d’audit', () => {
  it('enregistre une entrée avec son empreinte', async () => {
    const audit = new AuditService(admin);
    await audit.record({
      tenantId: T_A,
      acteurId: U_1,
      acteurRole: 'organisateur',
      action: 'event.create',
      cibleType: 'evenement',
    });
    // `max()` n'existe pas pour bytea : on lit l'empreinte directement.
    const r = await sql<{ n: number; h: Buffer }>`
      select count(*) over ()::int as n, empreinte as h from journal_audit limit 1
    `.execute(admin);
    expect(r.rows[0].n).toBe(1);
    expect(r.rows[0].h).toBeTruthy();
    expect(r.rows[0].h.length).toBe(32); // SHA-256
  });

  it('EXIGE un motif sur une action destructrice, et dit pourquoi', async () => {
    const audit = new AuditService(admin);
    await expect(
      audit.record({
        tenantId: T_A,
        acteurRole: 'organisateur',
        action: 'participant.disqualify',
        cibleType: 'participant',
      }),
    ).rejects.toThrow(/exige un motif/);
    await expect(
      audit.record({
        tenantId: T_A,
        acteurRole: 'organisateur',
        action: 'participant.disqualify',
        cibleType: 'participant',
      }),
    ).rejects.toThrow(/POURQUOI/);
  });

  it('accepte une action destructrice AVEC motif', async () => {
    const audit = new AuditService(admin);
    await expect(
      audit.record({
        tenantId: T_A,
        acteurRole: 'organisateur',
        action: 'participant.disqualify',
        cibleType: 'participant',
        motif: 'Règlement article 7 : inscription hors délai',
      }),
    ).resolves.toBeUndefined();
  });

  it('IMMUABLE : un UPDATE ne modifie rien', async () => {
    const audit = new AuditService(admin);
    await audit.record({
      tenantId: T_A,
      acteurRole: 'organisateur',
      action: 'event.create',
      cibleType: 'evenement',
    });

    // La règle DO INSTEAD NOTHING absorbe l'UPDATE sans erreur : rien ne change.
    await sql`update journal_audit set action = 'falsifie'`.execute(admin);
    const r = await sql<{ action: string }>`select action from journal_audit`.execute(
      admin,
    );
    expect(r.rows[0].action).toBe('event.create');
  });

  it('IMMUABLE : un DELETE ne supprime rien', async () => {
    const audit = new AuditService(admin);
    await audit.record({
      tenantId: T_A,
      acteurRole: 'organisateur',
      action: 'event.create',
      cibleType: 'evenement',
    });
    await sql`delete from journal_audit`.execute(admin);
    const r = await sql<{
      n: number;
    }>`select count(*)::int as n from journal_audit`.execute(admin);
    expect(r.rows[0].n).toBe(1);
  });

  it('le rôle applicatif n’a NI update NI delete au niveau des privilèges', async () => {
    // Deux barrières indépendantes : privilèges ET règles.
    const r = await sql<{ priv: string }>`
      select privilege_type as priv
      from information_schema.table_privileges
      where grantee = 'app_runtime' and table_name = 'journal_audit'
      order by privilege_type
    `.execute(admin);
    const privs = r.rows.map((x) => x.priv);
    expect(privs).toContain('SELECT');
    expect(privs).toContain('INSERT');
    expect(privs).not.toContain('UPDATE');
    expect(privs).not.toContain('DELETE');
  });

  it('la chaîne est valide sur une suite d’entrées', async () => {
    const audit = new AuditService(admin);
    for (let i = 0; i < 5; i++) {
      await audit.record({
        tenantId: T_A,
        acteurId: U_1,
        acteurRole: 'organisateur',
        action: `event.step${i}`,
        cibleType: 'evenement',
      });
    }
    const v = await audit.verifyChain(T_A);
    expect(v.valid).toBe(true);
    expect(v.checked).toBe(5);
  });

  it('DÉTECTE une entrée supprimée hors application', async () => {
    const audit = new AuditService(admin);
    for (let i = 0; i < 4; i++) {
      await audit.record({
        tenantId: T_A,
        acteurId: U_1,
        acteurRole: 'organisateur',
        action: `event.step${i}`,
        cibleType: 'evenement',
      });
    }

    // Suppression « par la bande » : on lève la règle, comme le ferait un
    // opérateur ayant accès à la base.
    await sql`drop rule journal_no_delete on journal_audit`.execute(admin);
    await sql`delete from journal_audit where action = 'event.step1'`.execute(admin);
    await sql`create rule journal_no_delete as on delete to journal_audit do instead nothing`.execute(
      admin,
    );

    const { logger, errors } = mkLogger();
    const v = await new AuditService(admin, logger).verifyChain(T_A);

    expect(v.valid).toBe(false);
    expect(v.brokenAt).toBeDefined();
    expect(errors[0]).toContain('ROMPUE');
    // Le diagnostic doit nommer la SUPPRESSION, pas rester vague : chercher
    // une modification quand une entrée a disparu fait perdre du temps.
    expect(errors[0]).toContain('SUPPRIMÉE');
    expect(errors[0]).toContain('chaînage');
    expect(errors[0]).toContain('Conservez une copie'); // dit quoi faire
  });

  it('DÉTECTE une entrée dont le CONTENU a été falsifié', async () => {
    // Le message d'erreur promet de détecter une entrée « supprimée OU
    // MODIFIÉE ». Détecter la suppression ne suffit donc pas : un opérateur qui
    // change l'action d'une entrée — « participant.disqualify » devenu
    // « participant.update » — doit casser la chaîne.
    //
    // TROUVÉ PAR LE LINTER : `verifyChain` calculait l'empreinte attendue puis
    // ne l'utilisait jamais (variable `expected` assignée sans lecture). Elle
    // ne comparait que le chaînage, donc la falsification passait.
    const audit = new AuditService(admin);
    for (let i = 0; i < 4; i++) {
      await audit.record({
        tenantId: T_A,
        acteurId: U_1,
        acteurRole: 'organisateur',
        action: `event.step${i}`,
        cibleType: 'evenement',
      });
    }

    // Modification « par la bande », comme le ferait un opérateur : on lève la
    // règle d'immuabilité, on change l'action, on la repose.
    await sql`drop rule journal_no_update on journal_audit`.execute(admin);
    await sql`update journal_audit set action = 'event.FALSIFIE'
              where action = 'event.step2'`.execute(admin);
    await sql`create rule journal_no_update as on update to journal_audit do instead nothing`.execute(
      admin,
    );

    // L'entrée a bien été modifiée : le test mesure ce qu'il prétend mesurer.
    const check = await sql<{ n: number }>`
      select count(*)::int as n from journal_audit where action = 'event.FALSIFIE'
    `.execute(admin);
    expect(check.rows[0].n).toBe(1);

    const { logger, errors } = mkLogger();
    const v = await new AuditService(admin, logger).verifyChain(T_A);

    expect(v.valid).toBe(false);
    expect(v.brokenAt).toBeDefined();
    expect(errors[0]).toContain('ROMPUE');
    // Le diagnostic distingue la MODIFICATION de la suppression.
    expect(errors[0]).toContain('MODIFIÉE');
    expect(errors[0]).toContain('empreinte');
    expect(errors[0]).not.toContain('SUPPRIMÉE');
  });

  it('chaîne vide : valide', async () => {
    const v = await new AuditService(admin).verifyChain(T_A);
    expect(v.valid).toBe(true);
    expect(v.checked).toBe(0);
  });

  /**
   * `list()` est ce que servira l'écran « Journal d'audit ».
   *
   * Elle n'était pas couverte : la méthode publique que verra un utilisateur
   * final était la seule du service à n'avoir jamais été exécutée.
   */
  describe('list — lecture du journal', () => {
    const T_C = '33333333-3333-3333-3333-333333333333';
    const EV_1 = 'eeee1111-0000-0000-0000-000000000001';
    const EV_2 = 'eeee2222-0000-0000-0000-000000000002';

    async function seed() {
      const audit = new AuditService(admin);
      // Deux évènements du tenant A, plus une entrée d'un AUTRE tenant.
      await sql`alter table tenant no force row level security`.execute(admin);
      await sql`insert into tenant (id, slug, nom)
                values (${T_C}, 'c', 'Tenant C')`.execute(admin);
      await sql`alter table tenant force row level security`.execute(admin);

      for (let i = 0; i < 3; i++) {
        await audit.record({
          tenantId: T_A,
          ressourceId: EV_1,
          acteurId: U_1,
          acteurRole: 'organisateur',
          action: `event.update.${i}`,
          cibleType: 'evenement',
        });
      }
      await audit.record({
        tenantId: T_A,
        ressourceId: EV_2,
        acteurId: U_1,
        acteurRole: 'organisateur',
        action: 'event.create',
        cibleType: 'evenement',
      });
      await audit.record({
        tenantId: T_C,
        acteurRole: 'proprietaire',
        action: 'tenant.create',
        cibleType: 'tenant',
      });
      return audit;
    }

    it('ne rend que les entrées du tenant demandé', async () => {
      const audit = await seed();
      const rows = (await audit.list(T_A)) as any[];
      expect(rows).toHaveLength(4);
      expect(rows.every((r) => r.tenant_id === T_A)).toBe(true);
      // L'entrée du tenant C n'apparaît pas — c'est le point.
      expect(rows.some((r) => r.tenant_id === T_C)).toBe(false);
    });

    it('rend les plus récentes d’abord', async () => {
      const audit = await seed();
      const rows = (await audit.list(T_A)) as any[];
      const ids = rows.map((r) => Number(r.id));
      expect(ids).toEqual([...ids].sort((a, b) => b - a));
    });

    it('filtre par ressource', async () => {
      const audit = await seed();
      const rows = (await audit.list(T_A, { ressourceId: EV_1 })) as any[];
      expect(rows).toHaveLength(3);
      expect(rows.every((r) => r.ressource_id === EV_1)).toBe(true);
    });

    it('respecte la limite demandée', async () => {
      const audit = await seed();
      const rows = (await audit.list(T_A, { limit: 2 })) as any[];
      expect(rows).toHaveLength(2);
    });

    it('PLAFONNE la limite à 1000, même si on demande plus', async () => {
      // Sans ce plafond, un appel `?limit=10000000` ferait du journal un
      // levier de déni de service — c'est la table qui grossit le plus vite.
      //
      // Mesure directe : on dépasse réellement le plafond. Avec 4 entrées
      // aucune limite ne se distingue, donc on en insère 1002.
      const audit = new AuditService(admin);
      const valeurs = Array.from(
        { length: 1002 },
        (_, i) =>
          sql`(${T_A}, ${U_1}, 'organisateur', ${`event.update.${i}`}, 'evenement')`,
      );
      await sql`
        insert into journal_audit
          (tenant_id, acteur_id, acteur_role, action, cible_type)
        values ${sql.join(valeurs)}
      `.execute(admin);

      const plafonne = (await audit.list(T_A, { limit: 999_999 })) as any[];
      expect(plafonne).toHaveLength(1000);

      // Et la valeur par défaut est bien 100.
      const defaut = (await audit.list(T_A)) as any[];
      expect(defaut).toHaveLength(100);
    });

    it('un tenant sans entrée rend une liste vide, pas une erreur', async () => {
      const audit = await seed();
      const rows = await audit.list('44444444-4444-4444-4444-444444444444');
      expect(rows).toEqual([]);
    });
  });
});
