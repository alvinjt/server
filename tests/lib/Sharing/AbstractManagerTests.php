<?php

/*
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

declare(strict_types=1);

namespace Test\Sharing;

use OCA\Sharing\ResponseDefinitions;
use OCA\Sharing\Tests\TestSharePermission;
use OCA\Sharing\Tests\TestSharePermission2;
use OCA\Sharing\Tests\TestSharePermissionCategory;
use OCA\Sharing\Tests\TestSharePermissionCategory2;
use OCA\Sharing\Tests\TestShareProperty;
use OCA\Sharing\Tests\TestShareProperty2;
use OCA\Sharing\Tests\TestSharePropertyFilter;
use OCA\Sharing\Tests\TestSharePropertyModifyValue;
use OCA\Sharing\Tests\TestShareRecipientType;
use OCA\Sharing\Tests\TestShareRecipientType2;
use OCA\Sharing\Tests\TestShareRecipientTypeArguments;
use OCA\Sharing\Tests\TestShareSourceType;
use OCA\Sharing\Tests\TestShareSourceType2;
use OCP\IUser;
use OCP\IUserManager;
use OCP\Server;
use OCP\Sharing\IManager;
use OCP\Sharing\IRegistry;
use OCP\Sharing\Permission\SharePermission;
use OCP\Sharing\Property\ShareProperty;
use OCP\Sharing\Recipient\ShareRecipient;
use OCP\Sharing\ShareAccessContext;
use OCP\Sharing\ShareState;
use OCP\Sharing\Source\ShareSource;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

/**
 * @psalm-import-type SharingShare from ResponseDefinitions
 * @psalm-import-type SharingRecipient from ResponseDefinitions
 */
abstract class AbstractManagerTests extends TestCase {
	abstract protected function searchRecipients(ShareAccessContext $accessContext, ?string $recipientTypeClass, string $query, int $limit, int $offset): array;

	abstract protected function createShare(ShareAccessContext $accessContext): array;

	abstract protected function updateShareState(ShareAccessContext $accessContext, string $id, ShareState $state): array;

	abstract protected function addShareSource(ShareAccessContext $accessContext, string $id, ShareSource $source): array;

	abstract protected function removeShareSource(ShareAccessContext $accessContext, string $id, ShareSource $source): array;

	abstract protected function addShareRecipient(ShareAccessContext $accessContext, string $id, ShareRecipient $recipient): array;

	abstract protected function removeShareRecipient(ShareAccessContext $accessContext, string $id, ShareRecipient $recipient): array;

	abstract protected function updateShareProperty(ShareAccessContext $accessContext, string $id, ShareProperty $property): array;

	abstract protected function updateSharePermission(ShareAccessContext $accessContext, string $id, SharePermission $permission): array;

	abstract protected function deleteShare(ShareAccessContext $accessContext, string $id): void;

	abstract protected function getShare(ShareAccessContext $accessContext, string $id): array;

	abstract protected function listShares(ShareAccessContext $accessContext, ?string $sourceType, ?string $lastShareID, ?int $limit): array;

	protected IManager $manager;

	protected IRegistry $registry;

	protected IUser $user1;

	protected IUser $user2;

	#[\Override]
	public function setUp(): void {
		parent::setUp();

		$this->manager = Server::get(IManager::class);

		$this->registry = Server::get(IRegistry::class);
		$this->registry->clear();

		$user1 = Server::get(IUserManager::class)->createUser('user1', 'password');
		$this->assertNotFalse($user1);
		$this->user1 = $user1;
		$this->user1->setDisplayName('User 1');

		$user2 = Server::get(IUserManager::class)->createUser('user2', 'password');
		$this->assertNotFalse($user2);
		$this->user2 = $user2;
		$this->user2->setDisplayName('User 2');
	}

	#[\Override]
	protected function tearDown(): void {
		$accessContext = new ShareAccessContext(force: true);

		foreach ($this->manager->listShares($accessContext, null, null, null) as $share) {
			$this->manager->deleteShare($accessContext, $share->id);
		}

		$this->registry->clear();

		$this->user1->delete();
		$this->user2->delete();

		parent::tearDown();
	}

	private function register(): void {
		$this->registry->registerSourceType(new TestShareSourceType(['source1' => 'Source 1']));
		$this->registry->registerSourceType(new TestShareSourceType2(['source2' => 'Source 2']));
		$this->registry->registerRecipientType(new TestShareRecipientType(['recipient1' => 'Recipient 1'], [], []));
		$this->registry->registerRecipientType(new TestShareRecipientType2(['recipient2' => 'Recipient 2'], [], []));
		$this->registry->registerProperty(new TestShareProperty(['valid1']));
		$this->registry->registerPropertyCompatibleWithSourceType(TestShareProperty::class, TestShareSourceType::class);
		$this->registry->registerPropertyCompatibleWithRecipientType(TestShareProperty::class, TestShareRecipientType::class);
		$this->registry->registerProperty(new TestShareProperty2(['valid2']));
		$this->registry->registerPropertyCompatibleWithSourceType(TestShareProperty2::class, TestShareSourceType2::class);
		$this->registry->registerPropertyCompatibleWithRecipientType(TestShareProperty2::class, TestShareRecipientType2::class);
		$this->registry->registerPermissionCategory(new TestSharePermissionCategory());
		$this->registry->registerPermissionCategory(new TestSharePermissionCategory2());
		$this->registry->registerPermission(TestShareSourceType::class, new TestSharePermission());
		$this->registry->registerPermission(TestShareSourceType2::class, new TestSharePermission2());
	}

	private function getTimestamp(): int {
		/** @psalm-suppress MixedReturnStatement */
		return self::invokePrivate($this->manager, 'generateLastUpdated');
	}

	public function testSearchRecipients(): void {
		$accessContext = new ShareAccessContext($this->user1);

		$displayNames = [
			'recipient1a' => 'Recipient 1A',
			'recipient1b' => 'Recipient 1B',
			'recipient1c' => 'Recipient 1C',
			'recipient2a' => 'Recipient 2A',
			'recipient2b' => 'Recipient 2B',
			'recipient2c' => 'Recipient 2C',
		];

		$recipientType1 = new TestShareRecipientType($displayNames, [], []);
		$recipientType2 = new TestShareRecipientType2($displayNames, [], []);
		$this->registry->registerRecipientType($recipientType1);
		$this->registry->registerRecipientType($recipientType2);

		$recipient1a = new ShareRecipient(TestShareRecipientType::class, 'recipient1a');
		$recipientType1->searchRecipients[] = $recipient1a;
		$recipient1b = new ShareRecipient(TestShareRecipientType::class, 'recipient1b');
		$recipientType1->searchRecipients[] = $recipient1b;
		$recipient1c = new ShareRecipient(TestShareRecipientType::class, 'recipient1c');
		$recipientType1->searchRecipients[] = $recipient1c;
		$recipient2a = new ShareRecipient(TestShareRecipientType2::class, 'recipient2a');
		$recipientType2->searchRecipients[] = $recipient2a;
		$recipient2b = new ShareRecipient(TestShareRecipientType2::class, 'recipient2b');
		$recipientType2->searchRecipients[] = $recipient2b;
		$recipient2c = new ShareRecipient(TestShareRecipientType2::class, 'recipient2c');
		$recipientType2->searchRecipients[] = $recipient2c;

		$this->assertEquals([
			['type' => TestShareRecipientType::class, 'value' => 'recipient1a', 'display_name' => $displayNames['recipient1a']],
			['type' => TestShareRecipientType::class, 'value' => 'recipient1b', 'display_name' => $displayNames['recipient1b']],
			['type' => TestShareRecipientType::class, 'value' => 'recipient1c', 'display_name' => $displayNames['recipient1c']],
			['type' => TestShareRecipientType2::class, 'value' => 'recipient2a', 'display_name' => $displayNames['recipient2a']],
			['type' => TestShareRecipientType2::class, 'value' => 'recipient2b', 'display_name' => $displayNames['recipient2b']],
			['type' => TestShareRecipientType2::class, 'value' => 'recipient2c', 'display_name' => $displayNames['recipient2c']],
		], $this->searchRecipients($accessContext, null, 'recipient', 10, 0));

		$this->assertEquals([
			['type' => TestShareRecipientType::class, 'value' => 'recipient1a', 'display_name' => $displayNames['recipient1a']],
			['type' => TestShareRecipientType::class, 'value' => 'recipient1b', 'display_name' => $displayNames['recipient1b']],
			['type' => TestShareRecipientType::class, 'value' => 'recipient1c', 'display_name' => $displayNames['recipient1c']],
		], $this->searchRecipients($accessContext, TestShareRecipientType::class, 'recipient', 10, 0));

		$this->assertEquals([
			['type' => TestShareRecipientType::class, 'value' => 'recipient1a', 'display_name' => $displayNames['recipient1a']],
		], $this->searchRecipients($accessContext, TestShareRecipientType::class, 'recipient', 1, 0));

		$this->assertEquals([
			['type' => TestShareRecipientType::class, 'value' => 'recipient1b', 'display_name' => $displayNames['recipient1b']],
			['type' => TestShareRecipientType::class, 'value' => 'recipient1c', 'display_name' => $displayNames['recipient1c']],
		], $this->searchRecipients($accessContext, TestShareRecipientType::class, 'recipient', 10, 1));
	}

	public function testSearchRecipientsUniqueDisplayNames(): void {
		$accessContext = new ShareAccessContext($this->user1);

		$recipientType1 = new TestShareRecipientType(['recipient1' => 'Recipient'], [], []);
		$recipientType2 = new TestShareRecipientType2(['recipient2' => 'Recipient', 'recipient3' => 'Other'], [], []);
		$this->registry->registerRecipientType($recipientType1);
		$this->registry->registerRecipientType($recipientType2);

		$recipient1 = new ShareRecipient(TestShareRecipientType::class, 'recipient1');
		$recipientType1->searchRecipients[] = $recipient1;
		$recipient2 = new ShareRecipient(TestShareRecipientType2::class, 'recipient2');
		$recipientType2->searchRecipients[] = $recipient2;
		$recipient3 = new ShareRecipient(TestShareRecipientType2::class, 'recipient3');
		$recipientType2->searchRecipients[] = $recipient3;

		$this->assertEquals([
			['type' => TestShareRecipientType::class, 'value' => 'recipient1', 'display_name' => 'Recipient (TestShareRecipientType: recipient1)'],
			['type' => TestShareRecipientType2::class, 'value' => 'recipient2', 'display_name' => 'Recipient (TestShareRecipientType2: recipient2)'],
			['type' => TestShareRecipientType2::class, 'value' => 'recipient3', 'display_name' => 'Other'],
		], $this->searchRecipients($accessContext, null, 'recipient', 10, 0));
	}

	public function testSearchRecipientsIcons(): void {
		$accessContext = new ShareAccessContext($this->user1);

		$recipientType = new TestShareRecipientType(['svg' => 'SVG', 'url' => 'URL'], [], []);
		$this->registry->registerRecipientType($recipientType);

		$recipient1 = new ShareRecipient(TestShareRecipientType::class, 'svg');
		$recipientType->searchRecipients[] = $recipient1;
		$recipient2 = new ShareRecipient(TestShareRecipientType::class, 'url');
		$recipientType->searchRecipients[] = $recipient2;

		$this->assertEquals([
			['type' => TestShareRecipientType::class, 'value' => 'svg', 'display_name' => 'SVG', 'icon' => ['svg' => '<svg/>']],
			['type' => TestShareRecipientType::class, 'value' => 'url', 'display_name' => 'URL', 'icon' => ['light' => 'https://example.com/light.png', 'dark' => 'https://example.com/dark.png',]],
		], $this->searchRecipients($accessContext, null, 'icon', 10, 0));
	}

	public function testCreateShare(): void {
		$this->register();

		$accessContext = new ShareAccessContext($this->user1);

		$before = $this->getTimestamp();
		$share = $this->createShare($accessContext);
		$after = $this->getTimestamp();
		unset($share['id']);
		$this->assertGreaterThanOrEqual($before, $share['last_updated']);
		$this->assertLessThanOrEqual($after, $share['last_updated']);
		unset($share['last_updated']);
		$this->assertEquals([
			'owner' => [
				'user_id' => $this->user1->getUID(),
				'display_name' => $this->user1->getDisplayName(),
				'icon' => [
					'light' => 'http://localhost/index.php/avatar/user1/64',
					'dark' => 'http://localhost/index.php/avatar/user1/64/dark',
				],
			],
			'state' => ShareState::Draft->value,
			'sources' => [],
			'recipients' => [],
			'properties' => [],
			'permissions' => [],
		], $share);
	}

	public function testUpdateShareState(): void {
		$this->register();

		$accessContext = new ShareAccessContext($this->user1);

		$id = $this->manager->createShare($accessContext);

		$before = $this->getTimestamp();
		$share = $this->updateShareState($accessContext, $id, ShareState::Active);
		$after = $this->getTimestamp();
		$this->assertGreaterThanOrEqual($before, $share['last_updated']);
		$this->assertLessThanOrEqual($after, $share['last_updated']);
		unset($share['last_updated']);
		$this->assertEquals([
			'id' => $id,
			'owner' => [
				'user_id' => $this->user1->getUID(),
				'display_name' => $this->user1->getDisplayName(),
				'icon' => [
					'light' => 'http://localhost/index.php/avatar/user1/64',
					'dark' => 'http://localhost/index.php/avatar/user1/64/dark',
				],
			],
			'state' => ShareState::Active->value,
			'sources' => [],
			'recipients' => [],
			'properties' => [],
			'permissions' => [],
		], $share);
	}

	public function testAddShareSource(): void {
		$this->register();

		$accessContext = new ShareAccessContext($this->user1);

		$id = $this->manager->createShare($accessContext);

		$before = $this->getTimestamp();
		$share = $this->addShareSource($accessContext, $id, new ShareSource(TestShareSourceType::class, 'source1'));
		$after = $this->getTimestamp();
		$this->assertGreaterThanOrEqual($before, $share['last_updated']);
		$this->assertLessThanOrEqual($after, $share['last_updated']);
		unset($share['last_updated']);
		$this->assertEquals([
			'id' => $id,
			'owner' => [
				'user_id' => $this->user1->getUID(),
				'display_name' => $this->user1->getDisplayName(),
				'icon' => [
					'light' => 'http://localhost/index.php/avatar/user1/64',
					'dark' => 'http://localhost/index.php/avatar/user1/64/dark',
				],
			],
			'state' => ShareState::Draft->value,
			'sources' => [
				[
					'type' => TestShareSourceType::class,
					'value' => 'source1',
					'display_name' => 'Source 1',
				],
			],
			'recipients' => [],
			'properties' => [],
			'permissions' => [
				[
					'type' => TestSharePermission::class,
					'display_name' => 'TestSharePermission',
					'category' => TestSharePermissionCategory::class,
					'enabled' => false,
				],
			],
		], $share);
	}

	public function testRemoveShareSource(): void {
		$this->register();

		$accessContext = new ShareAccessContext($this->user1);

		$id = $this->manager->createShare($accessContext);
		$this->manager->addShareSource($accessContext, $id, new ShareSource(TestShareSourceType::class, 'source1'));

		$before = $this->getTimestamp();
		$share = $this->removeShareSource($accessContext, $id, new ShareSource(TestShareSourceType::class, 'source1'));
		$after = $this->getTimestamp();
		$this->assertGreaterThanOrEqual($before, $share['last_updated']);
		$this->assertLessThanOrEqual($after, $share['last_updated']);
		unset($share['last_updated']);
		$this->assertEquals([
			'id' => $id,
			'owner' => [
				'user_id' => $this->user1->getUID(),
				'display_name' => $this->user1->getDisplayName(),
				'icon' => [
					'light' => 'http://localhost/index.php/avatar/user1/64',
					'dark' => 'http://localhost/index.php/avatar/user1/64/dark',
				],
			],
			'state' => ShareState::Draft->value,
			'sources' => [],
			'recipients' => [],
			'properties' => [],
			'permissions' => [],
		], $share);
	}

	public function testAddShareRecipient(): void {
		$this->register();

		$accessContext = new ShareAccessContext($this->user1);

		$id = $this->manager->createShare($accessContext);

		$before = $this->getTimestamp();
		$share = $this->addShareRecipient($accessContext, $id, new ShareRecipient(TestShareRecipientType::class, 'recipient1'));
		$after = $this->getTimestamp();
		$this->assertGreaterThanOrEqual($before, $share['last_updated']);
		$this->assertLessThanOrEqual($after, $share['last_updated']);
		unset($share['last_updated']);
		$this->assertEquals([
			'id' => $id,
			'owner' => [
				'user_id' => $this->user1->getUID(),
				'display_name' => $this->user1->getDisplayName(),
				'icon' => [
					'light' => 'http://localhost/index.php/avatar/user1/64',
					'dark' => 'http://localhost/index.php/avatar/user1/64/dark',
				],
			],
			'state' => ShareState::Draft->value,
			'sources' => [],
			'recipients' => [
				[
					'type' => TestShareRecipientType::class,
					'value' => 'recipient1',
					'display_name' => 'Recipient 1',
				],
			],
			'properties' => [],
			'permissions' => [],
		], $share);
	}

	public function testRemoveShareRecipient(): void {
		$this->register();

		$accessContext = new ShareAccessContext($this->user1);

		$id = $this->manager->createShare($accessContext);
		$this->manager->addShareRecipient($accessContext, $id, new ShareRecipient(TestShareRecipientType::class, 'recipient1'));

		$before = $this->getTimestamp();
		$share = $this->removeShareRecipient($accessContext, $id, new ShareRecipient(TestShareRecipientType::class, 'recipient1'));
		$after = $this->getTimestamp();
		$this->assertGreaterThanOrEqual($before, $share['last_updated']);
		$this->assertLessThanOrEqual($after, $share['last_updated']);
		unset($share['last_updated']);
		$this->assertEquals([
			'id' => $id,
			'owner' => [
				'user_id' => $this->user1->getUID(),
				'display_name' => $this->user1->getDisplayName(),
				'icon' => [
					'light' => 'http://localhost/index.php/avatar/user1/64',
					'dark' => 'http://localhost/index.php/avatar/user1/64/dark',
				],
			],
			'state' => ShareState::Draft->value,
			'sources' => [],
			'recipients' => [],
			'properties' => [],
			'permissions' => [],
		], $share);
	}

	/**
	 * @return list<array{list<?string>}>
	 */
	public static function dataProviderUpdateShareProperty(): array {
		return [
			[[null, 'valid1']],
			[['valid1', null]],
		];
	}

	/**
	 * @param list<?string> $values
	 */
	#[DataProvider('dataProviderUpdateShareProperty')]
	public function testUpdateShareProperty(array $values): void {
		$this->register();

		$accessContext = new ShareAccessContext($this->user1);

		$id = $this->manager->createShare($accessContext);
		$this->manager->addShareSource($accessContext, $id, new ShareSource(TestShareSourceType::class, 'source1'));
		$this->manager->addShareRecipient($accessContext, $id, new ShareRecipient(TestShareRecipientType::class, 'recipient1'));
		$this->manager->getShare($accessContext, $id);

		foreach ($values as $value) {
			$before = $this->getTimestamp();
			$share = $this->updateShareProperty($accessContext, $id, new ShareProperty(TestShareProperty::class, $value));
			$after = $this->getTimestamp();
			$this->assertGreaterThanOrEqual($before, $share['last_updated']);
			$this->assertLessThanOrEqual($after, $share['last_updated']);
			unset($share['last_updated']);
			$this->assertEquals([
				'id' => $id,
				'owner' => [
					'user_id' => $this->user1->getUID(),
					'display_name' => $this->user1->getDisplayName(),
					'icon' => [
						'light' => 'http://localhost/index.php/avatar/user1/64',
						'dark' => 'http://localhost/index.php/avatar/user1/64/dark',
					],
				],
				'state' => ShareState::Draft->value,
				'sources' => [
					[
						'type' => TestShareSourceType::class,
						'value' => 'source1',
						'display_name' => 'Source 1',
					],
				],
				'recipients' => [
					[
						'type' => TestShareRecipientType::class,
						'value' => 'recipient1',
						'display_name' => 'Recipient 1',
					],
				],
				'properties' => [
					[
						'type' => TestShareProperty::class,
						'display_name' => 'TestShareProperty',
						'priority' => 1,
						'required' => false,
						'value' => $value,
						'valid_values' => ['valid1'],
					],
				],
				'permissions' => [
					[
						'type' => TestSharePermission::class,
						'display_name' => 'TestSharePermission',
						'category' => TestSharePermissionCategory::class,
						'enabled' => false,
					],
				],
			], $share);
		}
	}

	public function testUpdateSharePropertyModifyProperties(): void {
		$this->registry->registerSourceType(new TestShareSourceType(['source' => 'Source']));
		$this->registry->registerRecipientType(new TestShareRecipientType(['recipient' => 'Recipient',], ['recipient'], []));
		$this->registry->registerProperty(new TestSharePropertyModifyValue());
		$this->registry->registerPropertyCompatibleWithSourceType(TestSharePropertyModifyValue::class, TestShareSourceType::class);
		$this->registry->registerPropertyCompatibleWithRecipientType(TestSharePropertyModifyValue::class, TestShareRecipientType::class);

		$accessContext = new ShareAccessContext($this->user1);

		$id = $this->manager->createShare($accessContext);
		$this->manager->addShareSource($accessContext, $id, new ShareSource(TestShareSourceType::class, 'source'));
		$this->manager->addShareRecipient($accessContext, $id, new ShareRecipient(TestShareRecipientType::class, 'recipient'));
		$this->manager->getShare($accessContext, $id);
		$this->manager->updateShareProperty($accessContext, $id, new ShareProperty(TestSharePropertyModifyValue::class, 'old-value'));

		$before = $this->getTimestamp();
		$share = $this->updateShareProperty($accessContext, $id, new ShareProperty(TestSharePropertyModifyValue::class, 'modify-on-save-old-value'));
		$after = $this->getTimestamp();
		$this->assertGreaterThanOrEqual($before, $share['last_updated']);
		$this->assertLessThanOrEqual($after, $share['last_updated']);
		unset($share['last_updated']);
		$this->assertEquals([
			'id' => $id,
			'owner' => [
				'user_id' => $this->user1->getUID(),
				'display_name' => $this->user1->getDisplayName(),
				'icon' => [
					'light' => 'http://localhost/index.php/avatar/user1/64',
					'dark' => 'http://localhost/index.php/avatar/user1/64/dark',
				],
			],
			'state' => ShareState::Draft->value,
			'sources' => [
				[
					'type' => TestShareSourceType::class,
					'value' => 'source',
					'display_name' => 'Source',
				],
			],
			'recipients' => [
				[
					'type' => TestShareRecipientType::class,
					'value' => 'recipient',
					'display_name' => 'Recipient',
				],
			],
			'properties' => [
				[
					'type' => TestSharePropertyModifyValue::class,
					'display_name' => 'TestSharePropertyModifyValue',
					'priority' => 1,
					'required' => false,
					'value' => 'old-value',
				],
			],
			'permissions' => [],
		], $share);

		$before = $this->getTimestamp();
		$share = $this->updateShareProperty($accessContext, $id, new ShareProperty(TestSharePropertyModifyValue::class, 'modify-on-save'));
		$after = $this->getTimestamp();
		$this->assertGreaterThanOrEqual($before, $share['last_updated']);
		$this->assertLessThanOrEqual($after, $share['last_updated']);
		unset($share['last_updated']);
		$this->assertEquals([
			'id' => $id,
			'owner' => [
				'user_id' => $this->user1->getUID(),
				'display_name' => $this->user1->getDisplayName(),
				'icon' => [
					'light' => 'http://localhost/index.php/avatar/user1/64',
					'dark' => 'http://localhost/index.php/avatar/user1/64/dark',
				],
			],
			'state' => ShareState::Draft->value,
			'sources' => [
				[
					'type' => TestShareSourceType::class,
					'value' => 'source',
					'display_name' => 'Source',
				],
			],
			'recipients' => [
				[
					'type' => TestShareRecipientType::class,
					'value' => 'recipient',
					'display_name' => 'Recipient',
				],
			],
			'properties' => [
				[
					'type' => TestSharePropertyModifyValue::class,
					'display_name' => 'TestSharePropertyModifyValue',
					'priority' => 1,
					'required' => false,
					'value' => 'modified-on-save',
				],
			],
			'permissions' => [],
		], $share);

		$before = $this->getTimestamp();
		$share = $this->updateShareProperty($accessContext, $id, new ShareProperty(TestSharePropertyModifyValue::class, 'modify-on-load'));
		$after = $this->getTimestamp();
		$this->assertGreaterThanOrEqual($before, $share['last_updated']);
		$this->assertLessThanOrEqual($after, $share['last_updated']);
		unset($share['last_updated']);
		$this->assertEquals([
			'id' => $id,
			'owner' => [
				'user_id' => $this->user1->getUID(),
				'display_name' => $this->user1->getDisplayName(),
				'icon' => [
					'light' => 'http://localhost/index.php/avatar/user1/64',
					'dark' => 'http://localhost/index.php/avatar/user1/64/dark',
				],
			],
			'state' => ShareState::Draft->value,
			'sources' => [
				[
					'type' => TestShareSourceType::class,
					'value' => 'source',
					'display_name' => 'Source',
				],
			],
			'recipients' => [
				[
					'type' => TestShareRecipientType::class,
					'value' => 'recipient',
					'display_name' => 'Recipient',
				],
			],
			'properties' => [
				[
					'type' => TestSharePropertyModifyValue::class,
					'display_name' => 'TestSharePropertyModifyValue',
					'priority' => 1,
					'required' => false,
					'value' => 'modified-on-load',
				],
			],
			'permissions' => [],
		], $share);
	}

	/**
	 * @return list<array{bool}>
	 */
	public static function dataProviderUpdateSharePermission(): array {
		return [
			[true],
			[false],
		];
	}

	#[DataProvider('dataProviderUpdateSharePermission')]
	public function testUpdateSharePermission(bool $enabled): void {
		$this->register();

		$accessContext = new ShareAccessContext($this->user1);

		$id = $this->manager->createShare($accessContext);
		$this->manager->addShareSource($accessContext, $id, new ShareSource(TestShareSourceType::class, 'source1'));
		$this->manager->getShare($accessContext, $id);

		$before = $this->getTimestamp();
		$share = $this->updateSharePermission($accessContext, $id, new SharePermission(TestSharePermission::class, $enabled));
		$after = $this->getTimestamp();
		$this->assertGreaterThanOrEqual($before, $share['last_updated']);
		$this->assertLessThanOrEqual($after, $share['last_updated']);
		unset($share['last_updated']);
		$this->assertEquals([
			'id' => $id,
			'owner' => [
				'user_id' => $this->user1->getUID(),
				'display_name' => $this->user1->getDisplayName(),
				'icon' => [
					'light' => 'http://localhost/index.php/avatar/user1/64',
					'dark' => 'http://localhost/index.php/avatar/user1/64/dark',
				],
			],
			'state' => ShareState::Draft->value,
			'sources' => [
				[
					'type' => TestShareSourceType::class,
					'value' => 'source1',
					'display_name' => 'Source 1',
				],
			],
			'recipients' => [],
			'properties' => [],
			'permissions' => [
				[
					'type' => TestSharePermission::class,
					'display_name' => 'TestSharePermission',
					'category' => TestSharePermissionCategory::class,
					'enabled' => $enabled,
				],
			],
		], $share);
	}

	public function testDeleteShare(): void {
		$this->register();

		$accessContext = new ShareAccessContext($this->user1);

		$id = $this->manager->createShare($accessContext);

		$this->deleteShare($accessContext, $id);

		$this->expectExceptionMessage('Share not found: ' . $id);
		$this->manager->getShare(new ShareAccessContext(force: true), $id);
	}

	public function testGetShare(): void {
		$this->register();

		$accessContext = new ShareAccessContext($this->user1);

		$before = $this->getTimestamp();
		$id = $this->manager->createShare($accessContext);
		$this->manager->addShareSource($accessContext, $id, new ShareSource(TestShareSourceType::class, 'source1'));
		$this->manager->addShareRecipient($accessContext, $id, new ShareRecipient(TestShareRecipientType::class, 'recipient1'));
		$this->manager->getShare($accessContext, $id);

		$after = $this->getTimestamp();

		$share = $this->getShare($accessContext, $id);
		$this->assertGreaterThanOrEqual($before, $share['last_updated']);
		$this->assertLessThanOrEqual($after, $share['last_updated']);
		unset($share['last_updated']);
		$this->assertEquals([
			'id' => $id,
			'owner' => [
				'user_id' => $this->user1->getUID(),
				'display_name' => $this->user1->getDisplayName(),
				'icon' => [
					'light' => 'http://localhost/index.php/avatar/user1/64',
					'dark' => 'http://localhost/index.php/avatar/user1/64/dark',
				],
			],
			'state' => ShareState::Draft->value,
			'sources' => [
				[
					'type' => TestShareSourceType::class,
					'value' => 'source1',
					'display_name' => 'Source 1',
				],
			],
			'recipients' => [
				[
					'type' => TestShareRecipientType::class,
					'value' => 'recipient1',
					'display_name' => 'Recipient 1',
				],
			],
			'properties' => [
				[
					'type' => TestShareProperty::class,
					'display_name' => 'TestShareProperty',
					'priority' => 1,
					'required' => false,
					'value' => null,
					'valid_values' => ['valid1'],
				],
			],
			'permissions' => [
				[
					'type' => TestSharePermission::class,
					'display_name' => 'TestSharePermission',
					'category' => TestSharePermissionCategory::class,
					'enabled' => false,
				],
			],
		], $share);
	}

	public function testGetShareAsRecipientNotActive(): void {
		$this->registry->registerSourceType(new TestShareSourceType(['source' => 'Source']));
		$this->registry->registerRecipientType(new TestShareRecipientType(['recipient1' => 'Recipient 1', 'recipient2' => 'Recipient 2'], ['recipient1'], []));

		$accessContext = new ShareAccessContext($this->user1);

		$id = $this->manager->createShare($accessContext);
		$this->manager->addShareSource($accessContext, $id, new ShareSource(TestShareSourceType::class, 'source'));
		$this->manager->addShareRecipient($accessContext, $id, new ShareRecipient(TestShareRecipientType::class, 'recipient1'));

		$this->expectExceptionMessage('Share not found: ' . $id);
		$this->getShare(new ShareAccessContext(currentUser: $this->user2), $id);
	}

	public function testGetShareAsRecipientActive(): void {
		$this->registry->registerSourceType(new TestShareSourceType(['source' => 'Source']));
		$this->registry->registerRecipientType(new TestShareRecipientType(['recipient1' => 'Recipient 1', 'recipient2' => 'Recipient 2'], ['recipient1'], []));

		$accessContext = new ShareAccessContext($this->user1);

		$before = $this->getTimestamp();
		$id = $this->manager->createShare($accessContext);
		$this->manager->addShareSource($accessContext, $id, new ShareSource(TestShareSourceType::class, 'source'));
		$this->manager->addShareRecipient($accessContext, $id, new ShareRecipient(TestShareRecipientType::class, 'recipient1'));
		$this->manager->addShareRecipient($accessContext, $id, new ShareRecipient(TestShareRecipientType::class, 'recipient2'));
		$this->manager->updateShareState($accessContext, $id, ShareState::Active);

		$after = $this->getTimestamp();

		$share = $this->getShare(new ShareAccessContext(currentUser: $this->user2), $id);
		$this->assertGreaterThanOrEqual($before, $share['last_updated']);
		$this->assertLessThanOrEqual($after, $share['last_updated']);
		unset($share['last_updated']);
		$this->assertEquals([
			'id' => $id,
			'owner' => [
				'user_id' => $this->user1->getUID(),
				'display_name' => $this->user1->getDisplayName(),
				'icon' => [
					'light' => 'http://localhost/index.php/avatar/user1/64',
					'dark' => 'http://localhost/index.php/avatar/user1/64/dark',
				],
			],
			'state' => ShareState::Active->value,
			'sources' => [
				[
					'type' => TestShareSourceType::class,
					'value' => 'source',
					'display_name' => 'Source',
				],
			],
			'recipients' => [
				[
					'type' => TestShareRecipientType::class,
					'value' => 'recipient1',
					'display_name' => 'Recipient 1',
				],
				[
					'type' => TestShareRecipientType::class,
					'value' => 'recipient2',
					'display_name' => 'Recipient 2',
				],
			],
			'properties' => [],
			'permissions' => [],
		], $share);
	}

	public function testGetShareAsRecipientWithArguments(): void {
		$this->registry->registerSourceType(new TestShareSourceType(['source' => 'Source']));
		$this->registry->registerRecipientType(new TestShareRecipientTypeArguments());

		$accessContext = new ShareAccessContext($this->user1);

		$before = $this->getTimestamp();
		$id = $this->manager->createShare($accessContext);
		$this->manager->addShareSource($accessContext, $id, new ShareSource(TestShareSourceType::class, 'source'));
		$this->manager->addShareRecipient($accessContext, $id, new ShareRecipient(TestShareRecipientTypeArguments::class, 'secret'));
		$this->manager->updateShareState($accessContext, $id, ShareState::Active);

		$after = $this->getTimestamp();

		$share = $this->getShare(new ShareAccessContext(currentUser: $this->user2, arguments: [TestShareRecipientTypeArguments::class => 'secret']), $id);
		$this->assertGreaterThanOrEqual($before, $share['last_updated']);
		$this->assertLessThanOrEqual($after, $share['last_updated']);
		unset($share['last_updated']);
		$this->assertEquals([
			'id' => $id,
			'owner' => [
				'user_id' => $this->user1->getUID(),
				'display_name' => $this->user1->getDisplayName(),
				'icon' => [
					'light' => 'http://localhost/index.php/avatar/user1/64',
					'dark' => 'http://localhost/index.php/avatar/user1/64/dark',
				],
			],
			'state' => ShareState::Active->value,
			'sources' => [
				[
					'type' => TestShareSourceType::class,
					'value' => 'source',
					'display_name' => 'Source',
				],
			],
			'recipients' => [
				[
					'type' => TestShareRecipientTypeArguments::class,
					'value' => 'secret',
					'display_name' => 'secret',
				],
			],
			'properties' => [],
			'permissions' => [],
		], $share);

		$this->expectExceptionMessage('Share not found: ' . $id);
		$this->getShare(new ShareAccessContext(currentUser: $this->user2), $id);
	}

	public function testGetShareAsNonRecipient(): void {
		$this->registry->registerSourceType(new TestShareSourceType(['source' => 'Source']));
		$this->registry->registerRecipientType(new TestShareRecipientType(['recipient1' => 'Recipient 1', 'recipient2' => 'Recipient 2'], [], []));

		$accessContext = new ShareAccessContext($this->user1);

		$id = $this->manager->createShare($accessContext);
		$this->manager->addShareSource($accessContext, $id, new ShareSource(TestShareSourceType::class, 'source'));
		$this->manager->addShareRecipient($accessContext, $id, new ShareRecipient(TestShareRecipientType::class, 'recipient1'));
		$this->manager->addShareRecipient($accessContext, $id, new ShareRecipient(TestShareRecipientType::class, 'recipient2'));
		$this->manager->updateShareState($accessContext, $id, ShareState::Active);

		$this->expectExceptionMessage('Share not found: ' . $id);
		$this->getShare(new ShareAccessContext(currentUser: $this->user2), $id);
	}

	public function testGetShareAsRecipientFilteredProperties(): void {
		$this->registry->registerSourceType(new TestShareSourceType(['source' => 'Source']));
		$this->registry->registerRecipientType(new TestShareRecipientType(['recipient' => 'Recipient'], ['recipient'], []));
		$this->registry->registerProperty(new TestSharePropertyFilter());
		$this->registry->registerPropertyCompatibleWithSourceType(TestSharePropertyFilter::class, TestShareSourceType::class);
		$this->registry->registerPropertyCompatibleWithRecipientType(TestSharePropertyFilter::class, TestShareRecipientType::class);

		$accessContext = new ShareAccessContext($this->user1);

		$before = $this->getTimestamp();
		$id = $this->manager->createShare($accessContext);
		$this->manager->addShareSource($accessContext, $id, new ShareSource(TestShareSourceType::class, 'source'));
		$this->manager->addShareRecipient($accessContext, $id, new ShareRecipient(TestShareRecipientType::class, 'recipient'));
		$this->manager->updateShareState($accessContext, $id, ShareState::Active);
		$this->manager->getShare($accessContext, $id);
		$this->manager->updateShareProperty($accessContext, $id, new ShareProperty(TestSharePropertyFilter::class, 'visible'));

		$after = $this->getTimestamp();

		$share = $this->getShare(new ShareAccessContext(currentUser: $this->user2), $id);
		$this->assertGreaterThanOrEqual($before, $share['last_updated']);
		$this->assertLessThanOrEqual($after, $share['last_updated']);
		unset($share['last_updated']);
		$this->assertEquals([
			'id' => $id,
			'owner' => [
				'user_id' => $this->user1->getUID(),
				'display_name' => $this->user1->getDisplayName(),
				'icon' => [
					'light' => 'http://localhost/index.php/avatar/user1/64',
					'dark' => 'http://localhost/index.php/avatar/user1/64/dark',
				],
			],
			'state' => ShareState::Active->value,
			'sources' => [
				[
					'type' => TestShareSourceType::class,
					'value' => 'source',
					'display_name' => 'Source',
				],
			],
			'recipients' => [
				[
					'type' => TestShareRecipientType::class,
					'value' => 'recipient',
					'display_name' => 'Recipient',
				],
			],
			'properties' => [
				[
					'type' => TestSharePropertyFilter::class,
					'display_name' => 'TestSharePropertyFilter',
					'priority' => 1,
					'required' => false,
					'value' => 'visible',
				],
			],
			'permissions' => [],
		], $share);

		$before = $this->getTimestamp();
		$this->manager->updateShareProperty($accessContext, $id, new ShareProperty(TestSharePropertyFilter::class, 'filtered'));
		$after = $this->getTimestamp();

		$share = $this->getShare(new ShareAccessContext(currentUser: $this->user1), $id);
		$this->assertGreaterThanOrEqual($before, $share['last_updated']);
		$this->assertLessThanOrEqual($after, $share['last_updated']);
		unset($share['last_updated']);
		$this->assertEquals([
			'id' => $id,
			'owner' => [
				'user_id' => $this->user1->getUID(),
				'display_name' => $this->user1->getDisplayName(),
				'icon' => [
					'light' => 'http://localhost/index.php/avatar/user1/64',
					'dark' => 'http://localhost/index.php/avatar/user1/64/dark',
				],
			],
			'state' => ShareState::Active->value,
			'sources' => [
				[
					'type' => TestShareSourceType::class,
					'value' => 'source',
					'display_name' => 'Source',
				],
			],
			'recipients' => [
				[
					'type' => TestShareRecipientType::class,
					'value' => 'recipient',
					'display_name' => 'Recipient',
				],
			],
			'properties' => [
				[
					'type' => TestSharePropertyFilter::class,
					'display_name' => 'TestSharePropertyFilter',
					'priority' => 1,
					'required' => false,
					'value' => 'filtered',
				],
			],
			'permissions' => [],
		], $share);

		$this->expectExceptionMessage('Share not found: ' . $id);
		$this->getShare(new ShareAccessContext(currentUser: $this->user2), $id);
	}

	public function testGetShareAsRecipientFilteredArguments(): void {
		$this->registry->registerSourceType(new TestShareSourceType(['source' => 'Source']));
		$this->registry->registerRecipientType(new TestShareRecipientType(['recipient' => 'Recipient'], ['recipient'], []));
		$this->registry->registerProperty(new TestSharePropertyFilter());
		$this->registry->registerPropertyCompatibleWithSourceType(TestSharePropertyFilter::class, TestShareSourceType::class);
		$this->registry->registerPropertyCompatibleWithRecipientType(TestSharePropertyFilter::class, TestShareRecipientType::class);

		$accessContext = new ShareAccessContext($this->user1);

		$before = $this->getTimestamp();
		$id = $this->manager->createShare($accessContext);
		$this->manager->addShareSource($accessContext, $id, new ShareSource(TestShareSourceType::class, 'source'));
		$this->manager->addShareRecipient($accessContext, $id, new ShareRecipient(TestShareRecipientType::class, 'recipient'));
		$this->manager->updateShareState($accessContext, $id, ShareState::Active);
		$this->manager->getShare($accessContext, $id);

		$after = $this->getTimestamp();

		$share = $this->getShare(new ShareAccessContext(currentUser: $this->user2), $id);
		$this->assertGreaterThanOrEqual($before, $share['last_updated']);
		$this->assertLessThanOrEqual($after, $share['last_updated']);
		unset($share['last_updated']);
		$this->assertEquals([
			'id' => $id,
			'owner' => [
				'user_id' => $this->user1->getUID(),
				'display_name' => $this->user1->getDisplayName(),
				'icon' => [
					'light' => 'http://localhost/index.php/avatar/user1/64',
					'dark' => 'http://localhost/index.php/avatar/user1/64/dark',
				],
			],
			'state' => ShareState::Active->value,
			'sources' => [
				[
					'type' => TestShareSourceType::class,
					'value' => 'source',
					'display_name' => 'Source',
				],
			],
			'recipients' => [
				[
					'type' => TestShareRecipientType::class,
					'value' => 'recipient',
					'display_name' => 'Recipient',
				],
			],
			'properties' => [
				[
					'type' => TestSharePropertyFilter::class,
					'display_name' => 'TestSharePropertyFilter',
					'priority' => 1,
					'required' => false,
					'value' => null,
				],
			],
			'permissions' => [],
		], $share);

		$share = $this->getShare(new ShareAccessContext(currentUser: $this->user1, arguments: [TestSharePropertyFilter::class => 'filtered']), $id);
		$this->assertGreaterThanOrEqual($before, $share['last_updated']);
		$this->assertLessThanOrEqual($after, $share['last_updated']);
		unset($share['last_updated']);
		$this->assertEquals([
			'id' => $id,
			'owner' => [
				'user_id' => $this->user1->getUID(),
				'display_name' => $this->user1->getDisplayName(),
				'icon' => [
					'light' => 'http://localhost/index.php/avatar/user1/64',
					'dark' => 'http://localhost/index.php/avatar/user1/64/dark',
				],
			],
			'state' => ShareState::Active->value,
			'sources' => [
				[
					'type' => TestShareSourceType::class,
					'value' => 'source',
					'display_name' => 'Source',
				],
			],
			'recipients' => [
				[
					'type' => TestShareRecipientType::class,
					'value' => 'recipient',
					'display_name' => 'Recipient',
				],
			],
			'properties' => [
				[
					'type' => TestSharePropertyFilter::class,
					'display_name' => 'TestSharePropertyFilter',
					'priority' => 1,
					'required' => false,
					'value' => null,
				],
			],
			'permissions' => [],
		], $share);

		$this->expectExceptionMessage('Share not found: ' . $id);
		$this->getShare(new ShareAccessContext(currentUser: $this->user2, arguments: [TestSharePropertyFilter::class => 'filtered']), $id);
	}

	public function testListShares(): void {
		$this->register();

		$accessContext = new ShareAccessContext($this->user1);

		$before1 = $this->getTimestamp();
		$id1 = $this->manager->createShare($accessContext);
		$this->manager->addShareSource($accessContext, $id1, new ShareSource(TestShareSourceType::class, 'source1'));
		$this->manager->addShareRecipient($accessContext, $id1, new ShareRecipient(TestShareRecipientType::class, 'recipient1'));
		$this->manager->getShare($accessContext, $id1);

		$after1 = $this->getTimestamp();

		$before2 = $this->getTimestamp();
		$id2 = $this->manager->createShare($accessContext);
		$this->manager->addShareSource($accessContext, $id2, new ShareSource(TestShareSourceType2::class, 'source2'));
		$this->manager->addShareRecipient($accessContext, $id2, new ShareRecipient(TestShareRecipientType2::class, 'recipient2'));
		$this->manager->getShare($accessContext, $id2);

		$after2 = $this->getTimestamp();

		$shares = $this->listShares($accessContext, null, null, null);
		$this->assertCount(2, $shares);
		$this->assertIsArray($shares[0]);
		$this->assertGreaterThanOrEqual($before1, $shares[0]['last_updated']);
		$this->assertLessThanOrEqual($after1, $shares[0]['last_updated']);
		$this->assertIsArray($shares[1]);
		$this->assertGreaterThanOrEqual($before2, $shares[1]['last_updated']);
		$this->assertLessThanOrEqual($after2, $shares[1]['last_updated']);
		unset($shares[0]['last_updated'], $shares[1]['last_updated']);
		$this->assertEquals([
			[
				'id' => $id1,
				'owner' => [
					'user_id' => $this->user1->getUID(),
					'display_name' => $this->user1->getDisplayName(),
					'icon' => [
						'light' => 'http://localhost/index.php/avatar/user1/64',
						'dark' => 'http://localhost/index.php/avatar/user1/64/dark',
					],
				],
				'state' => ShareState::Draft->value,
				'sources' => [
					[
						'type' => TestShareSourceType::class,
						'value' => 'source1',
						'display_name' => 'Source 1',
					],
				],
				'recipients' => [
					[
						'type' => TestShareRecipientType::class,
						'value' => 'recipient1',
						'display_name' => 'Recipient 1',
					],
				],
				'properties' => [
					[
						'type' => TestShareProperty::class,
						'display_name' => 'TestShareProperty',
						'priority' => 1,
						'required' => false,
						'value' => null,
						'valid_values' => ['valid1'],
					],
				],
				'permissions' => [
					[
						'type' => TestSharePermission::class,
						'display_name' => 'TestSharePermission',
						'category' => TestSharePermissionCategory::class,
						'enabled' => false,
					],
				],
			],
			[
				'id' => $id2,
				'owner' => [
					'user_id' => $this->user1->getUID(),
					'display_name' => $this->user1->getDisplayName(),
					'icon' => [
						'light' => 'http://localhost/index.php/avatar/user1/64',
						'dark' => 'http://localhost/index.php/avatar/user1/64/dark',
					],
				],
				'state' => ShareState::Draft->value,
				'sources' => [
					[
						'type' => TestShareSourceType2::class,
						'value' => 'source2',
						'display_name' => 'Source 2',
					],
				],
				'recipients' => [
					[
						'type' => TestShareRecipientType2::class,
						'value' => 'recipient2',
						'display_name' => 'Recipient 2',
					],
				],
				'properties' => [
					[
						'type' => TestShareProperty2::class,
						'display_name' => 'TestShareProperty2',
						'priority' => 1,
						'required' => false,
						'value' => null,
						'valid_values' => ['valid2'],
					],
				],
				'permissions' => [
					[
						'type' => TestSharePermission2::class,
						'display_name' => 'TestSharePermission2',
						'category' => TestSharePermissionCategory2::class,
						'enabled' => false,
					],
				],
			],
		], $shares);

		$shares = $this->listShares($accessContext, TestShareSourceType::class, null, null);
		$this->assertCount(1, $shares);
		$this->assertIsArray($shares[0]);
		$this->assertGreaterThanOrEqual($before1, $shares[0]['last_updated']);
		$this->assertLessThanOrEqual($after1, $shares[0]['last_updated']);
		unset($shares[0]['last_updated']);
		$this->assertEquals([
			[
				'id' => $id1,
				'owner' => [
					'user_id' => $this->user1->getUID(),
					'display_name' => $this->user1->getDisplayName(),
					'icon' => [
						'light' => 'http://localhost/index.php/avatar/user1/64',
						'dark' => 'http://localhost/index.php/avatar/user1/64/dark',
					],
				],
				'state' => ShareState::Draft->value,
				'sources' => [
					[
						'type' => TestShareSourceType::class,
						'value' => 'source1',
						'display_name' => 'Source 1',
					],
				],
				'recipients' => [
					[
						'type' => TestShareRecipientType::class,
						'value' => 'recipient1',
						'display_name' => 'Recipient 1',
					],
				],
				'properties' => [
					[
						'type' => TestShareProperty::class,
						'display_name' => 'TestShareProperty',
						'priority' => 1,
						'required' => false,
						'value' => null,
						'valid_values' => ['valid1'],
					],
				],
				'permissions' => [
					[
						'type' => TestSharePermission::class,
						'display_name' => 'TestSharePermission',
						'category' => TestSharePermissionCategory::class,
						'enabled' => false,
					],
				],
			],
		], $shares);

		$shares = $this->listShares($accessContext, null, $id1, null);
		$this->assertCount(1, $shares);
		$this->assertIsArray($shares[0]);
		$this->assertGreaterThanOrEqual($before2, $shares[0]['last_updated']);
		$this->assertLessThanOrEqual($after2, $shares[0]['last_updated']);
		unset($shares[0]['last_updated']);
		$this->assertEquals([
			[
				'id' => $id2,
				'owner' => [
					'user_id' => $this->user1->getUID(),
					'display_name' => $this->user1->getDisplayName(),
					'icon' => [
						'light' => 'http://localhost/index.php/avatar/user1/64',
						'dark' => 'http://localhost/index.php/avatar/user1/64/dark',
					],
				],
				'state' => ShareState::Draft->value,
				'sources' => [
					[
						'type' => TestShareSourceType2::class,
						'value' => 'source2',
						'display_name' => 'Source 2',
					],
				],
				'recipients' => [
					[
						'type' => TestShareRecipientType2::class,
						'value' => 'recipient2',
						'display_name' => 'Recipient 2',
					],
				],
				'properties' => [
					[
						'type' => TestShareProperty2::class,
						'display_name' => 'TestShareProperty2',
						'priority' => 1,
						'required' => false,
						'value' => null,
						'valid_values' => ['valid2'],
					],
				],
				'permissions' => [
					[
						'type' => TestSharePermission2::class,
						'display_name' => 'TestSharePermission2',
						'category' => TestSharePermissionCategory2::class,
						'enabled' => false,
					],
				],
			],
		], $shares);

		$shares = $this->listShares($accessContext, null, null, 1);
		$this->assertCount(1, $shares);
		$this->assertIsArray($shares[0]);
		$this->assertGreaterThanOrEqual($before1, $shares[0]['last_updated']);
		$this->assertLessThanOrEqual($after1, $shares[0]['last_updated']);
		unset($shares[0]['last_updated']);
		$this->assertEquals([
			[
				'id' => $id1,
				'owner' => [
					'user_id' => $this->user1->getUID(),
					'display_name' => $this->user1->getDisplayName(),
					'icon' => [
						'light' => 'http://localhost/index.php/avatar/user1/64',
						'dark' => 'http://localhost/index.php/avatar/user1/64/dark',
					],
				],
				'state' => ShareState::Draft->value,
				'sources' => [
					[
						'type' => TestShareSourceType::class,
						'value' => 'source1',
						'display_name' => 'Source 1',
					],
				],
				'recipients' => [
					[
						'type' => TestShareRecipientType::class,
						'value' => 'recipient1',
						'display_name' => 'Recipient 1',
					],
				],
				'properties' => [
					[
						'type' => TestShareProperty::class,
						'display_name' => 'TestShareProperty',
						'priority' => 1,
						'required' => false,
						'value' => null,
						'valid_values' => ['valid1'],
					],
				],
				'permissions' => [
					[
						'type' => TestSharePermission::class,
						'display_name' => 'TestSharePermission',
						'category' => TestSharePermissionCategory::class,
						'enabled' => false,
					],
				],
			],
		], $shares);
	}
}
