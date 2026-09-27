import { Controller, Get, Module, SetMetadata, Injectable } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { TenancyModule } from './tenancy.module.js';
import { TenantContext } from './context/tenant-context.js';
import { SESSION_VALIDE } from './tenant.interceptor.js';
import { SESSION_REQUISE } from './tokens.js';
import { beforeAll, afterAll, it, expect } from '@jest/globals';
import { Kysely, PostgresDialect, sql } from 'kysely';
import pg from 'pg';
import { PoolDeTest } from './fixtures/pool-test.js';
import { runMigrations } from './migrations/runner.js';
import { RoleService } from './roles/role-service.js';
import { buildAbility, assertCan } from './authorization/ability.js';
import { AuditService } from './audit/audit-service.js';
import { TEST_CREDENTIALS } from './test-globals.js';

const base = `tenancy_l8_${process.pid}`;
const connexion = {
  host: '127.0.0.1',
  port: 55432,
  user: 'postgres',
  password: 'probe',
};
const gestion = new pg.Client({ ...connexion, database: 'postgres' });
const db = new Kysely<any>({
  dialect: new PostgresDialect({
    pool: new PoolDeTest({ ...connexion, database: base }),
  }),
});
const runtime = new Kysely<any>({
  dialect: new PostgresDialect({
    pool: new PoolDeTest({
      ...connexion,
      database: base,
      user: 'app_runtime',
      password: TEST_CREDENTIALS.runtime,
    }),
  }),
});
const tenant = '11111111-1111-1111-1111-111111111111';
const utilisateur = '22222222-2222-2222-2222-222222222222';
const piece = '33333333-3333-3333-3333-333333333333';
const autre = '44444444-4444-4444-4444-444444444444';

beforeAll(async () => {
  await gestion.connect();
  await gestion.query(`create database ${base}`);
  await runMigrations(db, { credentials: TEST_CREDENTIALS });
});
afterAll(async () => {
  await runtime.destroy();
  await db.destroy();
  await gestion.query(`drop database ${base} with (force)`);
  await gestion.end();
});

it('L8 — tenant sans colonnes métier et sans pays obligatoire', async () => {
  const colonnes = await sql<{
    column_name: string;
  }>`select column_name from information_schema.columns where table_name = 'tenant'`.execute(
    db,
  );
  for (const colonne of ['pays', 'rccm', 'raison_sociale']) {
    expect(colonnes.rows.map((c) => c.column_name)).not.toContain(colonne);
  }
  await expect(
    sql`insert into tenant (slug, nom) values ('maison', 'Maison')`.execute(db),
  ).resolves.toBeDefined();
});

it('L8 — les rôles système viennent exclusivement du consommateur', async () => {
  expect(await new RoleService(db).ensureSystemRoles()).toEqual([]);
  expect(
    await new RoleService(db).ensureSystemRoles([
      { code: 'decorateur', libelle: 'Décorateur', permissions: [] },
    ]),
  ).toEqual(['decorateur']);
});

it('L8 — CASL juge le meuble par pieceId', () => {
  const contexte = {
    tenantId: tenant,
    userId: utilisateur,
    permissions: ['meuble.deplacer'],
    scopedResourceIds: [piece],
  };
  const capacite = buildAbility(contexte, { champsPortee: { meuble: 'pieceId' } });
  expect(() =>
    assertCan(capacite, 'deplacer', 'meuble', { id: autre, pieceId: piece }),
  ).not.toThrow();
  expect(() =>
    assertCan(capacite, 'deplacer', 'meuble', { id: piece, pieceId: autre }),
  ).toThrow(/portée/);
});

it('L8 — app_runtime ne peut plus écrire dans permission', async () => {
  const droits = await sql<{
    insertion: boolean;
    modification: boolean;
    suppression: boolean;
  }>`select has_table_privilege(current_user, 'permission', 'INSERT') as insertion, has_table_privilege(current_user, 'permission', 'UPDATE') as modification, has_table_privilege(current_user, 'permission', 'DELETE') as suppression`.execute(
    runtime,
  );
  expect(droits.rows[0]).toEqual({
    insertion: false,
    modification: false,
    suppression: false,
  });
});

it('L8 — la base filtre le journal par portée sous app_runtime', async () => {
  // La valeur pays permet de constater le défaut de portée avant de déplacer le schéma.
  const colonnes = await sql<{
    existe: boolean;
  }>`select exists(select 1 from information_schema.columns where table_name = 'tenant' and column_name = 'pays') as existe`.execute(
    db,
  );
  if (colonnes.rows[0].existe)
    await sql`insert into tenant (id, slug, nom, pays) values (${tenant}, 'audit', 'Audit', 'CM')`.execute(
      db,
    );
  else
    await sql`insert into tenant (id, slug, nom) values (${tenant}, 'audit', 'Audit')`.execute(
      db,
    );
  await sql`insert into utilisateur (id, auth_sub, email) values (${utilisateur}, 'lecteur', 'lecteur@example.test')`.execute(
    db,
  );
  await sql`insert into permission (code) values ('audit.read') on conflict do nothing`.execute(
    db,
  );
  const role = await new RoleService(db).createTenantRole(tenant, {
    code: 'lecteur',
    libelle: 'Lecteur',
    permissions: ['audit.read'],
  });
  await sql`insert into appartenance (tenant_id, utilisateur_id, role_id, portee_ressource_id) values (${tenant}, ${utilisateur}, ${role.id}, ${piece})`.execute(
    db,
  );
  for (const ressourceId of [piece, autre, undefined])
    await new AuditService(db).record({
      tenantId: tenant,
      ressourceId,
      acteurRole: 'lecteur',
      action: 'lecture',
      cibleType: 'piece',
    });
  await runtime.transaction().execute(async (trx) => {
    await sql`select set_config('app.tenant', ${tenant}, true), set_config('app.user', ${utilisateur}, true)`.execute(
      trx,
    );
    const lignes = await sql<{
      ressource_id: string;
    }>`select ressource_id from journal_audit`.execute(trx);
    expect(lignes.rows).toEqual([{ ressource_id: piece }]);
    const permission = await sql<{
      ici: boolean;
      ailleurs: boolean;
      globale: boolean;
    }>`select app_a_permission_portee('audit.read', ${piece}::uuid) as ici, app_a_permission_portee('audit.read', ${autre}::uuid) as ailleurs, app_a_permission_portee('audit.read', null) as globale`.execute(
      trx,
    );
    expect(permission.rows[0]).toEqual({ ici: true, ailleurs: false, globale: false });
  });
});

it('L8 — forRoot protège HTTP et propage le contexte jusqu’à PostgreSQL', async () => {
  const module = await Test.createTestingModule({
    imports: [
      TenancyModule.forRoot({
        imports: [BaseModule],
        connexion: BASE,
        identite: {
          useValue: {
            extract: (requete: unknown) => {
              const req = requete as {
                headers: Record<string, string>;
                url: string;
                [SESSION_VALIDE]?: boolean;
              };
              resolutions++;
              if (req.url === '/ignorer') throw new Error('Identité ignorée attendue');
              if (req.headers['x-identite'] === 'sans-appartenance')
                req[SESSION_VALIDE] = true;
              if (req.headers['x-identite'] === 'lecteur')
                return { tenantId: tenant, userId: utilisateur };
              if (req.headers['x-identite'] === 'inconnu')
                return { tenantId: tenant, userId: autre };
              return undefined;
            },
          },
        },
        permissions: {
          useValue: {
            resolve: (_type: unknown, methode: string) =>
              methode === 'journal' ? 'audit.read' : undefined,
          },
        },
        ignorerContexte: (r) => (r as { url: string }).url === '/ignorer',
        gardesAvant: [Avant],
        gardesApres: [Apres],
      }),
    ],
    controllers: [MaisonControleur],
  }).compile();
  const app = module.createNestApplication({ logger: false });
  await app.listen(0, '127.0.0.1');
  const adresse = await app.getUrl();
  const lire = (route: string, identite = '') =>
    fetch(`${adresse}/${route}`, { headers: { 'x-identite': identite } });
  try {
    expect((await lire('journal')).status).toBe(401);
    expect((await lire('journal', 'sans-appartenance')).status).toBe(403);
    expect((await lire('journal', 'inconnu')).status).toBe(403);
    expect((await lire('session')).status).toBe(401);
    expect((await lire('session', 'sans-appartenance')).status).toBe(403);
    expect((await lire('session', 'lecteur')).status).toBe(200);
    expect((await lire('public')).status).toBe(200);
    expect((await lire('ignorer')).status).toBe(200);
    ordre.length = 0;
    const avant = resolutions;
    const reponse = await lire('journal', 'lecteur');
    expect(reponse.status).toBe(200);
    expect(await reponse.json()).toEqual([{ ressource_id: piece }]);
    expect(resolutions - avant).toBe(1);
    expect(ordre).toEqual(['avant', 'apres']);
  } finally {
    await app.close();
  }
});

const BASE = Symbol('base');
let resolutions = 0;
const ordre: string[] = [];
@Module({ providers: [{ provide: BASE, useValue: runtime }], exports: [BASE] })
class BaseModule {}
@Injectable()
class Avant {
  canActivate() {
    ordre.push('avant');
    return true;
  }
}
@Injectable()
class Apres {
  canActivate() {
    ordre.push('apres');
    return true;
  }
}
@Controller()
class MaisonControleur {
  constructor(private readonly contexte: TenantContext) {}
  @Get('journal')
  async journal() {
    await Promise.resolve();
    return this.contexte.withContext(
      async (trx) =>
        (await sql`select ressource_id from journal_audit`.execute(trx)).rows,
    );
  }
  @Get('session')
  @SetMetadata(SESSION_REQUISE, true)
  session() {
    return { ok: true };
  }
  @Get('public')
  publique() {
    return { ok: true };
  }
  @Get('ignorer')
  ignorer() {
    return { ok: true };
  }
}

it('L8 — les rôles préinstallés se vérifient sans superuser ni mot de passe', async () => {
  const { assurerRole } = await import('./migrations/001-roles.js');
  await assurerRole(
    runtime,
    {
      name: 'app_runtime',
      options: 'login nobypassrls nosuperuser nocreatedb nocreaterole',
    },
    { rolesExistants: true },
  );
  await expect(
    assurerRole(
      runtime,
      { name: `absent_l8_${process.pid}`, options: 'nologin' },
      { rolesExistants: true },
    ),
  ).rejects.toThrow(/absent.*administrateur/);
  const avant =
    await sql`select rolname, rolpassword from pg_authid where rolname like 'app_%' order by rolname`.execute(
      db,
    );
  await sql`delete from tenancy_migrations where name = '001-roles'`.execute(db);
  await runMigrations(db, { rolesExistants: true });
  expect(
    (
      await sql`select rolname, rolpassword from pg_authid where rolname like 'app_%' order by rolname`.execute(
        db,
      )
    ).rows,
  ).toEqual(avant.rows);
});

it('L1 — la rotation explicite fonctionne sur un rôle jetable, sans toucher aux rôles partagés', async () => {
  const { randomUUID } = await import('node:crypto');
  const { assurerRole } = await import('./migrations/001-roles.js');
  const nom = `test_l8_${randomUUID().replaceAll('-', '')}`;
  const role = {
    name: nom,
    password: randomUUID(),
    options: 'login nobypassrls nosuperuser',
  };
  try {
    await assurerRole(db, role);
    const empreinte = async () =>
      (
        await sql<{
          mot: string;
        }>`select rolpassword as mot from pg_authid where rolname = ${nom}`.execute(db)
      ).rows[0].mot;
    const avant = await empreinte();
    await assurerRole(db, role, { realignerMotsDePasse: true });
    expect(await empreinte()).not.toBe(avant);
    const conservee = await empreinte();
    await assurerRole(
      db,
      { ...role, password: randomUUID() },
      { rolesExistants: true, realignerMotsDePasse: true },
    );
    expect(await empreinte()).toBe(conservee);
  } finally {
    await sql`drop role if exists ${sql.id(nom)}`.execute(db);
  }
});
