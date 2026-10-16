/*
 * Copyright 2012-present the original author or authors.
 */

package org.springframework.boot.ssl;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

import javax.net.ssl.SSLContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.util.Assert;

/**
 * Default {@link SslBundleRegistry} implementation.
 *
 * @author Scott Frederick
 * @author Moritz Halbritter
 * @author Phillip Webb
 * @author Jonatan Ivanov
 * @since 3.1.0
 */
public class DefaultSslBundleRegistry implements SslBundleRegistry, SslBundles {

	private static final Log logger = LogFactory.getLog(DefaultSslBundleRegistry.class);

	private final Map<String, RegisteredSslBundle> registeredBundles = new ConcurrentHashMap<>();

	private final List<BiConsumer<String, SslBundle>> registerHandlers = new CopyOnWriteArrayList<>();

	public DefaultSslBundleRegistry() {
	}

	public DefaultSslBundleRegistry(String name, SslBundle bundle) {
		registerBundle(name, bundle);
	}

	@Override
	public void registerBundle(String name, SslBundle bundle) {
		Assert.notNull(name, "'name' must not be null");
		Assert.notNull(bundle, "'bundle' must not be null");
		RegisteredSslBundle previous = this.registeredBundles.putIfAbsent(name, new RegisteredSslBundle(name, bundle));
		Assert.state(previous == null, () -> "Cannot replace existing SSL bundle '%s'".formatted(name));
		this.registerHandlers.forEach((handler) -> handler.accept(name, bundle));
	}

	@Override
	public void updateBundle(String name, SslBundle updatedBundle) {
		getRegistered(name).update(updatedBundle);
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * The returned bundle has stable object identity and delegates to the bundle that is
	 * registered under the given name at the time each method is called. A caller that
	 * retains the returned instance will therefore see the result of any subsequent
	 * {@link #updateBundle(String, SslBundle) update}.
	 */
	@Override
	public SslBundle getBundle(String name) {
		return getRegistered(name);
	}

	@Override
	public void addBundleUpdateHandler(String name, Consumer<SslBundle> updateHandler) throws NoSuchSslBundleException {
		getRegistered(name).addUpdateHandler(updateHandler);
	}

	@Override
	public void addBundleRegisterHandler(BiConsumer<String, SslBundle> registerHandler) {
		this.registerHandlers.add(registerHandler);
	}

	@Override
	public List<String> getBundleNames() {
		List<String> names = new ArrayList<>(this.registeredBundles.keySet());
		Collections.sort(names);
		return Collections.unmodifiableList(names);
	}

	private RegisteredSslBundle getRegistered(String name) throws NoSuchSslBundleException {
		Assert.notNull(name, "'name' must not be null");
		RegisteredSslBundle registered = this.registeredBundles.get(name);
		if (registered == null) {
			throw new NoSuchSslBundleException(name, "SSL bundle name '%s' cannot be found".formatted(name));
		}
		return registered;
	}

	/**
	 * An {@link SslBundle} registered under a name, with stable object identity across
	 * updates.
	 * <p>
	 * Each method resolves the currently registered bundle rather than caching anything,
	 * so there is no window in which a retained reference can disagree with the registry.
	 * This is what allows technologies that capture an {@code SslBundle} once, such as
	 * Kafka's {@code SslBundleSslEngineFactory}, to pick up reloaded trust material
	 * without being handed a new instance.
	 */
	private static final class RegisteredSslBundle implements SslBundle {

		private final String name;

		private final List<Consumer<SslBundle>> updateHandlers = new CopyOnWriteArrayList<>();

		private volatile SslBundle bundle;

		RegisteredSslBundle(String name, SslBundle bundle) {
			this.name = name;
			this.bundle = bundle;
		}

		void update(SslBundle updatedBundle) {
			Assert.notNull(updatedBundle, "'updatedBundle' must not be null");
			this.bundle = updatedBundle;
			if (this.updateHandlers.isEmpty()) {
				logger.warn(LogMessage.format(
						"SSL bundle '%s' has been updated but may be in use by a technology that doesn't support SSL reloading",
						this.name));
			}
			this.updateHandlers.forEach((handler) -> handler.accept(updatedBundle));
		}

		void addUpdateHandler(Consumer<SslBundle> updateHandler) {
			Assert.notNull(updateHandler, "'updateHandler' must not be null");
			this.updateHandlers.add(updateHandler);
		}

		@Override
		public SslStoreBundle getStores() {
			return this.bundle.getStores();
		}

		@Override
		public SslBundleKey getKey() {
			return this.bundle.getKey();
		}

		@Override
		public SslOptions getOptions() {
			return this.bundle.getOptions();
		}

		@Override
		public String getProtocol() {
			return this.bundle.getProtocol();
		}

		@Override
		public SslManagerBundle getManagers() {
			return this.bundle.getManagers();
		}

		/**
		 * {@inheritDoc}
		 * <p>
		 * Resolves the registered bundle once so that the context is built from a single
		 * coherent bundle. The inherited default calls {@link #getManagers()} and
		 * {@link #getProtocol()} separately, which a concurrent update could fall
		 * between.
		 */
		@Override
		public SSLContext createSslContext() {
			return this.bundle.createSslContext();
		}

		@Override
		public String toString() {
			return this.bundle.toString();
		}

	}

}
