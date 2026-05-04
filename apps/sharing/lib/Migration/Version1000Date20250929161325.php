<?php

/**
 * SPDX-FileCopyrightText: 2025 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

declare(strict_types=1);


namespace OCA\Sharing\Migration;

use Closure;
use Doctrine\DBAL\Schema\SchemaException;
use OCP\DB\ISchemaWrapper;
use OCP\DB\Types;
use OCP\Migration\IOutput;
use OCP\Migration\SimpleMigrationStep;
use Override;

final class Version1000Date20250929161325 extends SimpleMigrationStep {
	/**
	 * @param Closure():ISchemaWrapper $schemaClosure
	 * @throws SchemaException
	 */
	#[Override]
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
		$schema = $schemaClosure();

		$shareTable = $schema->createTable('sharing_share');
		$shareTable->addColumn('id', Types::BIGINT);
		$shareTable->addColumn('owner', Types::TEXT);
		$shareTable->addColumn('last_updated', Types::BIGINT);
		$shareTable->addColumn('state', Types::TEXT);
		$shareTable->setPrimaryKey(['id']);

		$sourcesTable = $schema->createTable('sharing_share_sources');
		$sourcesTable->addColumn('id', Types::BIGINT);
		$sourcesTable->addColumn('source_type', Types::TEXT);
		$sourcesTable->addColumn('source_value', Types::TEXT);
		$sourcesTable->setPrimaryKey(['id', 'source_type', 'source_value']);
		$sourcesTable->addForeignKeyConstraint($shareTable->getName(), ['id'], ['id'], ['onDelete' => 'CASCADE']);

		$recipientsTable = $schema->createTable('sharing_share_recipients');
		$recipientsTable->addColumn('id', Types::BIGINT);
		$recipientsTable->addColumn('recipient_type', Types::TEXT);
		$recipientsTable->addColumn('recipient_value', Types::TEXT);
		$recipientsTable->setPrimaryKey(['id', 'recipient_type', 'recipient_value']);
		$recipientsTable->addForeignKeyConstraint($shareTable->getName(), ['id'], ['id'], ['onDelete' => 'CASCADE']);

		$propertiesTable = $schema->createTable('sharing_share_properties');
		$propertiesTable->addColumn('id', Types::BIGINT);
		$propertiesTable->addColumn('property_type', Types::TEXT);
		$propertiesTable->addColumn('property_value', Types::TEXT, ['notnull' => false]);
		$propertiesTable->setPrimaryKey(['id', 'property_type']);
		$propertiesTable->addForeignKeyConstraint($shareTable->getName(), ['id'], ['id'], ['onDelete' => 'CASCADE']);

		$permissionsTable = $schema->createTable('sharing_share_permissions');
		$permissionsTable->addColumn('id', Types::BIGINT);
		$permissionsTable->addColumn('permission_type', Types::TEXT);
		$permissionsTable->addColumn('permission_enabled', Types::BOOLEAN);
		$permissionsTable->setPrimaryKey(['id', 'permission_type']);
		$permissionsTable->addForeignKeyConstraint($shareTable->getName(), ['id'], ['id'], ['onDelete' => 'CASCADE']);

		return $schema;
	}
}
