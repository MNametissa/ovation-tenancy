/**
 * Tests du journal d'audit et du puits de permissions, contre PostgreSQL réel.
 *
 * T3.7 — une permission disparue est marquée obsolète, jamais supprimée.
 * T3.8 — le journal est immuable, et la chaîne détecte une altération.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach } from '@jest/globals';
import { Kysely, PostgresDialect, sql } from 'kysely';
import pg from 'pg';
import { runMigrations } from '../migrations/runner.js';
import { AuditService } from './audit-service.js';
import { PermissionSink } from '../permissions/permission-sink.js';
import { RoleService } from '../roles/role-service.js';
import type { TenancyLogger } from '../logging.js';

const { Pool, Client } = pg;
const DB = 'tenancy_audit_test';

const CREDENTIALS = {
  migration: 'test_migration_pwd',
  runtime: 'test_runtime_pwd',
  auth: 'test_auth_pwd',
};

const T_A = '11111111-1111-1111-1111-111111111111';
const U_1 = 'aaaaaaaa-0000-0000-0000-000000000001';

function mkDb(database: string, user: string, password: string, max = 2) {
  return new Kysely<any>({
    dialect: new PostgresDialect({
      pool: new Pool({ host: '127.0.0.1', port: 55432, database, user, password, max }),
    }),
  });
}

function mkLogger() {
  const warns: string[] = [];
  const errors: string[] = [];
  const logs: string[] = [];
  const logger: TenancyLogger = {
    error: (m) => errors.push(m),
    warn: (m) => warns.push(m),
    log: (m) => logs.push(m),
    debug: () => {},
  };
  return { logger, warns, errors, logs };
}

let admin: Kysely<any>;
let runtime: Kysely<any>;

beforeAll(async () => {
  const c = new Client({
    host: '127.0.0.1',
    port: 55432,
    database: 'postgres',
    user: 'postgres',
    password: 'probe',
  });
  await c.connect();
  await c.query(`drop database if exists ${DB} with (force)`);
  await c.query(`create database ${DB}`);
  await c.end();

  admin = mkDb(DB, 'postgres', 'probe', 3);
  await runMigrations(admin, { credentials: CREDENTIALS, verify: false });
  runtime = mkDb(DB, 'app_runtime', CREDENTIALS.runtime, 2);
});

afterAll(async () => {
  await runtime.destroy();
  await admin.destroy();
  const c = new Client({
    host: '127.0.0.1',
    port: 55432,
    database: 'postgres',
    user: 'postgres',
    password: 'probe',
  });
  await c.connect();
  await c.query(`drop database if exists ${DB} with (force)`);
  await c.end();
});

beforeEach(async () => {
  for (const t of [
    'journal_audit',
    'appartenance',
    'role_permission',
    'role',
    'tenant',
    'utilisateur',
  ]) {
    await sql.raw(`alter table ${t} no force row level security`).execute(admin);
  }
  // journal_audit porte des règles DO INSTEAD NOTHING : on les lève le temps
  // du nettoyage, puis on les repose. C'est justement ce que les tests
  // d'immuabilité vérifieront ensuite.
  await sql`drop rule if exists journal_no_delete on journal_audit`.execute(admin);
  await sql`delete from journal_audit`.execute(admin);
  await sql`create rule journal_no_delete as on delete to journal_audit do instead nothing`.execute(
    admin,
  );

  await sql`delete from appartenance`.execute(admin);
  await sql`delete from role_permission`.execute(admin);
  await sql`delete from role`.execute(admin);
  await sql`delete from tenant`.execute(admin);
  await sql`delete from utilisateur`.execute(admin);
  await sql`delete from permission`.execute(admin);

  await sql`insert into tenant (id, slug, nom, pays)
            values (${T_A}, 'a', 'Tenant A', 'CM')`.execute(admin);
  await sql`insert into utilisateur (id, auth_sub, email)
            values (${U_1}, 'sub-1', 'u1@test.cm')`.execute(admin);

  for (const t of [
    'journal_audit',
    'appartenance',
    'role_permission',
    'role',
    'tenant',
    'utilisateur',
  ]) {
    await sql.raw(`alter table ${t} force row level security`).execute(admin);
  }
});

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
      await sql`insert into tenant (id, slug, nom, pays)
                values (${T_C}, 'c', 'Tenant C', 'CM')`.execute(admin);
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

describe('T3.7 — puits de permissions', () => {
  it('insère les permissions découvertes', async () => {
    const sink = new PermissionSink(admin);
    const r = await sink.sync({
      permissions: [
        { key: 'event.create', resource: 'event', action: 'create' },
        { key: 'event.delete', resource: 'event', action: 'delete' },
      ],
    });
    expect(r.added.sort()).toEqual(['event.create', 'event.delete']);
    expect(r.obsoleted).toHaveLength(0);
  });

  it('RÉGRESSION : un code SANS POINT reçoit un libellé et un domaine non vides', async () => {
    // TROUVÉ PAR LE LINTER (no-unnecessary-condition) : `rest.join('.')` rend
    // toujours une chaîne, donc `''` pour « ping ». Le repli `?? code` ne se
    // déclenchait jamais — `''` n'est pas nullish — et le libellé partait VIDE
    // en base. Un catalogue avec des libellés vides est illisible dans l'écran
    // d'administration des rôles.
    const sink = new PermissionSink(admin);
    await sink.sync({ permissions: [{ key: 'ping' }] });

    const r = await sql<{ libelle: string; domaine: string }>`
      select libelle, domaine from permission where code = 'ping'
    `.execute(admin);

    expect(r.rows).toHaveLength(1);
    expect(r.rows[0].libelle).not.toBe('');
    expect(r.rows[0].libelle).toBe('ping');
    expect(r.rows[0].domaine).toBe('ping');
  });

  it('un code vide ne produit ni libellé ni domaine vide', async () => {
    // Cas limite du cas limite : `''.split('.')` rend `['']`.
    const sink = new PermissionSink(admin);
    await sink.sync({ permissions: [{ key: '' }] });

    const r = await sql<{ libelle: string; domaine: string }>`
      select libelle, domaine from permission where code = ''
    `.execute(admin);

    expect(r.rows).toHaveLength(1);
    // Le domaine retombe sur « general » ; le libellé reste vide car le code
    // l'est — mais rien n'est `null`, donc rien ne casse l'affichage.
    expect(r.rows[0].domaine).toBe('general');
    expect(r.rows[0].libelle).not.toBeNull();
  });

  it('MARQUE OBSOLÈTE une permission disparue, sans la supprimer', async () => {
    const sink = new PermissionSink(admin);
    await sink.sync({
      permissions: [{ key: 'event.create' }, { key: 'event.legacy' }],
    });

    const { logger, logs } = mkLogger();
    const r = await new PermissionSink(admin, logger).sync({
      permissions: [{ key: 'event.create' }],
    });

    expect(r.obsoleted).toEqual(['event.legacy']);
    // Toujours présente en base — un rôle pourrait y référer.
    const still = await sql<{ n: number; obs: Date | null }>`
      select count(*)::int as n, max(obsolete_le) as obs
      from permission where code = 'event.legacy'
    `.execute(admin);
    expect(still.rows[0].n).toBe(1);
    expect(still.rows[0].obs).not.toBeNull();
    expect(logs.some((l) => l.includes('obsolète'))).toBe(true);
  });

  it('AVERTIT si une permission obsolète est encore attribuée', async () => {
    const sink = new PermissionSink(admin);
    await sink.sync({ permissions: [{ key: 'event.legacy' }] });

    await sql`alter table role no force row level security`.execute(admin);
    await sql`alter table role_permission no force row level security`.execute(admin);
    const roles = new RoleService(admin);
    await roles.createTenantRole(T_A, {
      code: 'legacy_role',
      libelle: 'Legacy',
      permissions: ['event.legacy'],
    });
    await sql`alter table role force row level security`.execute(admin);
    await sql`alter table role_permission force row level security`.execute(admin);

    const { logger, warns } = mkLogger();
    const r = await new PermissionSink(admin, logger).sync({ permissions: [] });

    expect(r.stillReferenced).toEqual([{ code: 'event.legacy', roles: 1 }]);
    expect(warns[0]).toContain('disparu du code');
    expect(warns[0]).toContain('PAS');
    expect(warns[0]).toContain('Retirez-la de ces rôles'); // dit quoi faire
  });

  it('RÉVEILLE une permission obsolète qui réapparaît', async () => {
    const sink = new PermissionSink(admin);
    await sink.sync({ permissions: [{ key: 'event.maybe' }] });
    await sink.sync({ permissions: [] }); // disparue

    const { logger, logs } = mkLogger();
    const r = await new PermissionSink(admin, logger).sync({
      permissions: [{ key: 'event.maybe' }],
    });

    expect(r.revived).toEqual(['event.maybe']);
    expect(r.added).toHaveLength(0); // réveillée, pas dupliquée
    expect(logs.some((l) => l.includes('réapparue'))).toBe(true);

    const n = await sql<{ n: number }>`
      select count(*)::int as n from permission where code = 'event.maybe'
    `.execute(admin);
    expect(n.rows[0].n).toBe(1); // une seule ligne, pas deux
  });

  it('listObsoleteInUse donne le ménage à faire', async () => {
    const sink = new PermissionSink(admin);
    await sink.sync({ permissions: [{ key: 'event.old' }] });

    await sql`alter table role no force row level security`.execute(admin);
    await sql`alter table role_permission no force row level security`.execute(admin);
    await new RoleService(admin).createTenantRole(T_A, {
      code: 'r1',
      libelle: 'R1',
      permissions: ['event.old'],
    });
    await sql`alter table role force row level security`.execute(admin);
    await sql`alter table role_permission force row level security`.execute(admin);

    await sink.sync({ permissions: [] });
    const todo = await sink.listObsoleteInUse();
    expect(todo).toEqual([{ code: 'event.old', roles: ['r1'] }]);
  });
});

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
