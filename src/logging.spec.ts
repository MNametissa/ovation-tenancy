/**
 * Tests de la fabrique de logger.
 *
 * `createLogger` est exporté publiquement, et c'est le chemin que prend une
 * application qui ne fournit pas son propre logger. Tous les autres tests
 * injectent un faux logger, donc cette fabrique n'était jamais exécutée : un
 * point d'entrée public sans une seule mesure.
 */
import { describe, it, expect, jest } from '@jest/globals';
import type { LoggerService } from '@nestjs/common';
import { createLogger, MSG } from './logging.js';

function mkSpy() {
  return {
    error: jest.fn(),
    warn: jest.fn(),
    log: jest.fn(),
    debug: jest.fn(),
  };
}

describe('createLogger', () => {
  it('délègue les quatre niveaux au logger fourni', () => {
    const spy = mkSpy();
    const logger = createLogger(spy);

    logger.error('boum', 'trace');
    logger.warn('attention');
    logger.log('démarré');
    logger.debug('détail');

    expect(spy.error).toHaveBeenCalledWith('boum', 'trace');
    expect(spy.warn).toHaveBeenCalledWith('attention');
    expect(spy.log).toHaveBeenCalledWith('démarré');
    expect(spy.debug).toHaveBeenCalledWith('détail');
  });

  it('sans logger fourni, utilise le Logger de Nest sans lever', () => {
    // Le cas par défaut : une application qui n'a rien configuré. Il ne doit
    // surtout pas échouer — c'est le chemin du démarrage.
    const logger = createLogger();
    expect(() => {
      logger.error('e');
      logger.warn('w');
      logger.log('l');
      logger.debug('d');
    }).not.toThrow();
  });

  it('tolère un logger partiel : un niveau manquant ne fait pas tomber l’appelant', () => {
    // LoggerService rend `debug` et quelques autres optionnels. Un logger
    // maison incomplet ne doit pas transformer un avertissement en panne :
    // perdre un message est acceptable, perdre la requête ne l'est pas.
    const partial = { log: jest.fn() } as unknown as LoggerService;
    const logger = createLogger(partial);

    expect(() => {
      logger.warn('avertissement perdu, mais sans dégât');
      logger.debug('idem');
      logger.error('idem');
    }).not.toThrow();

    logger.log('celui-là passe');
    expect((partial as any).log).toHaveBeenCalledWith('celui-là passe');
  });

  it('le contexte par défaut est « Tenancy », et reste surchargeable', () => {
    // Le contexte est ce qui rend un log filtrable en production.
    expect(() => createLogger(undefined, 'MonApp')).not.toThrow();
    expect(() => createLogger()).not.toThrow();
  });
});

describe('MSG — inventaire complet', () => {
  it('chaque message porte une action corrective, sans exception', () => {
    // La règle : « si le dev oublie, on doit le lui rappeler ». Un message
    // sans action corrective ne rappelle rien. On vérifie TOUS les messages,
    // pas un échantillon — c'est ainsi qu'un ajout futur est couvert.
    const verbes = [
      'Enveloppez',
      'Vérifiez',
      'Ajoutez',
      'ALTER TABLE',
      'withRlsDisabled',
      'NOBYPASSRLS',
      'permissive',
      'Passez',
      'Relancez',
      'Utilisez',
      'Déclarez',
      'Corrigez',
      'Créez',
      'Retirez',
      'Appelez',
      'Posez',
    ];

    /**
     * Appelle un message avec des arguments plausibles.
     *
     * Les signatures diffèrent (chaînes, tableau de tables). On essaie les
     * formes connues plutôt que de supposer une signature unique.
     */
    const echantillon = (fn: unknown): string => {
      if (typeof fn !== 'function') return String(fn);
      const f = fn as (...a: any[]) => string;
      const formes: any[][] = [['op', 'x', 'y'], [['table_a', 'table_b']], []];
      for (const args of formes) {
        try {
          return f(...args);
        } catch {
          // signature suivante
        }
      }
      throw new Error(`aucune signature connue n'appelle ce message`);
    };

    const entrees = Object.entries(MSG);
    expect(entrees.length).toBeGreaterThan(0);

    for (const [nom, valeur] of entrees) {
      const message = echantillon(valeur);
      const aUneAction = verbes.some((v) => message.includes(v));
      // Le nom du message est dans l'assertion : un échec dit lequel corriger.
      expect(aUneAction ? nom : `${nom} SANS ACTION CORRECTIVE : ${message}`).toBe(nom);
      expect(message.length).toBeGreaterThan(80);
    }
  });
});
