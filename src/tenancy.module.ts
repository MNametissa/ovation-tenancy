import {
  Module,
  type DynamicModule,
  type InjectionToken,
  type Provider,
  type Type,
  type CanActivate,
} from '@nestjs/common';
import { APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { ClsModule } from 'nestjs-cls';
import { ClsPluginTransactional } from '@nestjs-cls/transactional';
import { TransactionalAdapterKysely } from '@nestjs-cls/transactional-adapter-kysely';
import { TenantContext } from './context/tenant-context.js';
import {
  IdentitySource,
  TenantInterceptor,
  IGNORER_CONTEXTE,
} from './tenant.interceptor.js';
import { PermissionGuard } from './permission.guard.js';
import { CONNEXION_TENANCY, ResolutionPermissions } from './tokens.js';

/** Provider dont le jeton est fixé par le module. */
type SansJeton<T> = T extends { provide: InjectionToken } ? Omit<T, 'provide'> : never;
type Fournisseur = SansJeton<Provider>;
export interface OptionsTenancy {
  imports: NonNullable<DynamicModule['imports']>;
  connexion: InjectionToken;
  identite: Fournisseur;
  permissions: Fournisseur;
  /** Routes sans contexte (authentification, par exemple). */
  ignorerContexte?: (requete: unknown) => boolean;
  /** Ordre explicite : débit, permission, puis règles métier. */
  gardesAvant?: Type<CanActivate>[];
  gardesApres?: Type<CanActivate>[];
}

@Module({})
export class TenancyModule {
  static forRoot(options: OptionsTenancy): DynamicModule {
    const avant = options.gardesAvant ?? [];
    const apres = options.gardesApres ?? [];
    return {
      module: TenancyModule,
      global: true,
      imports: [
        ...options.imports,
        ClsModule.forRoot({
          global: true,
          middleware: { mount: true },
          plugins: [
            new ClsPluginTransactional({
              imports: options.imports,
              adapter: new TransactionalAdapterKysely({
                kyselyInstanceToken: options.connexion,
              }),
            }),
          ],
        }),
      ],
      providers: [
        { provide: CONNEXION_TENANCY, useExisting: options.connexion },
        { ...options.identite, provide: IdentitySource } as Provider,
        { ...options.permissions, provide: ResolutionPermissions } as Provider,
        { provide: IGNORER_CONTEXTE, useValue: options.ignorerContexte },
        TenantContext,
        TenantInterceptor,
        PermissionGuard,
        ...avant,
        ...apres,
        ...[...avant, PermissionGuard, ...apres].map((garde) => ({
          provide: APP_GUARD,
          useExisting: garde,
        })),
        { provide: APP_INTERCEPTOR, useExisting: TenantInterceptor },
      ],
      exports: [TenantContext, IdentitySource, PermissionGuard, ...avant, ...apres],
    };
  }
}
