import pg from 'pg';

/**
 * Pool des TESTS : écoute ses erreurs. Une suite qui supprime sa base en fin de
 * test coupe les connexions inactives ; sans écouteur, `pg` émet `error` sur le
 * pool et Node en fait une exception non rattrapée — MESURÉ : la suite entière
 * tombait par intermittence (« Test suite failed to run »), tous tests verts.
 */
export class PoolDeTest extends pg.Pool {
  constructor(options?: pg.PoolConfig) {
    super(options);
    this.on('error', () => {});
  }
}
