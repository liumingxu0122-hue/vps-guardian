# Controller host coexistence baseline

This is a sanitized, read-only inventory captured before the Phase 4 Completion Sprint. It exists
to detect collateral changes. It is not an authorization to remove, restart, or reconfigure
non-Guardian services.

## Guardian scope

- Four project containers: Controller, Web, Agent Gateway, and PostgreSQL.
- Three project networks: backend, Agent ingress, and Agent edge.
- Project volumes include PostgreSQL data, Controller data, Web state, backup state/cache, and
  recovery exchange.
- Host services include the Guardian Agent and a dedicated Phase 4C synthetic fixture.
- Public browser traffic terminates at host Nginx and is forwarded to a loopback-only Web listener.
- Agent ingress remains a distinct listener and mTLS boundary.

## Coexisting scope

At audit time the host also ran ten non-Guardian containers across several unrelated applications,
their databases, caches, object storage, and search services. It also ran a Komari server container
and a Komari Agent service.

The host had multiple non-Guardian Docker networks and volumes. None is a Guardian migration
target. Names and private identifiers are intentionally omitted from this committed document.

## Runtime and storage

- Docker and containerd were active.
- Docker root was already on the mounted secondary data filesystem.
- Root filesystem utilization was below the migration risk threshold.
- Public ports 80/443 were owned by host Nginx.
- PostgreSQL's published host port was loopback-only.
- The browser-side Guardian listener was loopback-only.
- The Agent Gateway used its dedicated listener.

## Change guard

The Phase 4 sprint must not:

- stop, delete, recreate, rename, or reconfigure a non-Guardian container;
- remove or alter Komari, its data, or any Komari Agent;
- change DNS or unrelated reverse-proxy sites;
- change proxy-node services or subscriptions;
- make global Docker, containerd, firewall, SSH, user, or permission changes;
- migrate runtime data while root capacity remains below the agreed risk threshold.

Before and after every Staging deployment, compare:

1. non-Guardian container names, image identities, health, and restart counts;
2. active non-Guardian system services;
3. listening ports and owners;
4. Docker network and volume sets;
5. root and secondary-filesystem utilization;
6. Komari server and Agent health.

Any unexplained difference is a deployment gate failure and must trigger Guardian rollback without
attempting an automatic repair of the unrelated service.
