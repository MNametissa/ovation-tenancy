import { describe, it, expect } from '@jest/globals';
import { sql } from 'kysely';
import { PermissionSink } from './permission-sink.js';
import { RoleService } from '../roles/role-service.js';
import { installerBancAudit, admin, T_A, mkLogger } from '../fixtures/audit-banc.js';
installerBancAudit('tenancy_catalogue_test');

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
