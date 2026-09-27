import 'reflect-metadata';
import { it, expect } from '@jest/globals';
import { Test } from '@nestjs/testing';
import { Module } from '@nestjs/common';
import {
  Kysely,
  DummyDriver,
  PostgresAdapter,
  PostgresIntrospector,
  PostgresQueryCompiler,
} from 'kysely';
import { TenancyModule } from './tenancy.module.js';
import { TenantContext } from './context/tenant-context.js';

const BASE = Symbol('base');
const db = new Kysely<any>({
  dialect: {
    createDriver: () => new DummyDriver(),
    createAdapter: () => new PostgresAdapter(),
    createIntrospector: (k) => new PostgresIntrospector(k),
    createQueryCompiler: () => new PostgresQueryCompiler(),
  },
});
@Module({ providers: [{ provide: BASE, useValue: db }], exports: [BASE] })
class BaseModule {}

it('L8 — forRoot fournit le contexte CLS sans câblage manuel', async () => {
  const module = await Test.createTestingModule({
    imports: [
      TenancyModule.forRoot({
        imports: [BaseModule],
        connexion: BASE,
        identite: { useValue: { extract: () => undefined } },
        permissions: { useValue: { resolve: () => undefined } },
      }),
    ],
  }).compile();
  try {
    const contexte = module.get(TenantContext);
    expect(contexte.tenantId).toBeUndefined();
    await contexte.run({ tenantId: 'maison', userId: 'habitant' }, async () => {
      expect(contexte.tenantId).toBe('maison');
      expect(contexte.userId).toBe('habitant');
    });
  } finally {
    await module.close();
    await db.destroy();
  }
});

it('L8 — garde et intercepteur laissent les transports non HTTP à leur contexte explicite', async () => {
  const { PermissionGuard } = await import('./permission.guard.js');
  const { TenantInterceptor, resoudreIdentite } =
    await import('./tenant.interceptor.js');
  const { Reflector } = await import('@nestjs/core');
  const { of, firstValueFrom } = await import('rxjs');
  const contexte = {
    getType: () => 'rpc',
  } as import('@nestjs/common').ExecutionContext;
  const identite = { extract: () => undefined };
  const garde = new PermissionGuard(
    { resolve: () => undefined },
    identite,
    db,
    new Reflector(),
  );
  expect(await garde.canActivate(contexte)).toBe(true);
  const intercepteur = new TenantInterceptor({} as TenantContext, identite);
  expect(
    await firstValueFrom(
      await intercepteur.intercept(contexte, { handle: () => of('message') }),
    ),
  ).toBe('message');
  expect(await resoudreIdentite(identite, undefined)).toBeUndefined();
});
