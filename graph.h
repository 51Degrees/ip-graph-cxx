/* *********************************************************************
 * This Original Work is copyright of 51 Degrees Mobile Experts Limited.
 * Copyright 2025 51 Degrees Mobile Experts Limited, Davidson House,
 * Forbury Square, Reading, Berkshire, United Kingdom RG1 3EU.
 *
 * This Original Work is licensed under the European Union Public Licence (EUPL) 
 * v.1.2 and is subject to its terms as set out below.
 *
 * If a copy of the EUPL was not distributed with this file, You can obtain
 * one at https://opensource.org/licenses/EUPL-1.2.
 *
 * The 'Compatible Licences' set out in the Appendix to the EUPL (as may be
 * amended by the European Commission) shall be deemed incompatible for
 * the purposes of the Work and the provisions of the compatibility
 * clause in Article 5 of the EUPL shall not apply.
 * 
 * If using the Work as, or as part of, a network application, by 
 * including the attribution notice(s) required under Article 5 of the EUPL
 * in the end user terms of the application under an appropriate heading, 
 * such notice(s) shall fulfill the requirements of that article.
 * 
 * [TODO INSERT PATENT NOTICE]
 * 
 * ********************************************************************* */

#ifndef FIFTYONE_DEGREES_IPI_GRAPH_INCLUDED
#define FIFTYONE_DEGREES_IPI_GRAPH_INCLUDED

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <math.h>
#include <time.h>
#include <ctype.h>
#include <assert.h>
#ifdef _MSC_VER
#include <windows.h>
#endif
#include "../common-cxx/data.h"
#include "../common-cxx/exceptions.h"
#include "../common-cxx/collection.h"
#include "../common-cxx/list.h"
#include "../common-cxx/status.h"
#include "../common-cxx/array.h"

 /**
 * @ingroup FiftyOneDegreesIpIntelligence
 * @defgroup FiftyOneDegreesIpIntelligenceApi IpIntelligence
 *
 * All the functions specific to the IP Intelligence Graph.
 * @{
 */

#if !defined(DEBUG) && !defined(_DEBUG) && !defined(NDEBUG)
#define NDEBUG
#endif

/**
 * DATA STRUCTURES
 */

/**
 * Data structure used to extract a value from the bytes that form a fixed
 * width graph node.
 */
#pragma pack(push, 1)
typedef struct fiftyone_degrees_ipi_cg_member_t {
	uint64_t mask; /**< Mask applied to a record to obtain the members bits */
	uint64_t shift; /**< Left shift to apply to the result of the mask to
				    obtain the value */
} fiftyoneDegreesIpiCgMember;
#pragma pack(pop)

/**
 * Collection header information for graph collections.
 */
#pragma pack(push, 1)
typedef struct fiftyone_degrees_ipi_cg_member_collection_t {
	uint32_t length; /**< Number of bytes that form the collection */
	uint32_t count; /**< Number of bit packed records in the collection */
	uint32_t startPosition; /**< Position of the first collection byte */
} fiftyoneDegreesIpiCgMemberCollection;
#pragma pack(pop)

/**
 * Data structure used for the values collection.
 */
#pragma pack(push, 1)
typedef struct fiftyone_degrees_ipi_cg_member_value_t {
	fiftyoneDegreesIpiCgMemberCollection collection;
	uint16_t recordSize; /**< Number of bits that for the value record */
	fiftyoneDegreesIpiCgMember unequalFlag; /**< Bit for the not equal flag */
	fiftyoneDegreesIpiCgMember value; /**< Bits for the value */
} fiftyoneDegreesIpiCgMemberValue;
#pragma pack(pop)

/**
 * Fixed width record in the collection where the record relates to a component
 * and IP version. All the information needed to evaluate the graph with an IP
 * address is available in the structure.
 */
#pragma pack(push, 1)
typedef struct fiftyone_degrees_ipi_cg_info_t {
	byte version; /**< IP address version (4 or 6). The reason byte is used
				  instead of fiftyoneDegreesIpEvidenceType, is that enum is not
			      necessarily a fixed size, so the struct may not always map to
				  the data file. The value can still be cast to the enum type
				  fiftyoneDegreesIpEvidenceType */
	byte componentId; /**< The component id the graph relates to. */
	
	uint32_t graphIndex; /**< The index to the entry record in the header data
						 structure for the graph. */
	fiftyoneDegreesIpiCgMemberCollection variable;
	fiftyoneDegreesIpiCgMemberValue value;
} fiftyoneDegreesIpiCgInfo;
#pragma pack(pop)

/**
 * The information and a working collection to retrieve entries from the 
 * component graph.
 */
typedef struct fiftyone_degrees_ipi_cg_t {
	fiftyoneDegreesIpiCgInfo* info;
	fiftyoneDegreesCollection* values; /**< Values collection */
	fiftyoneDegreesCollection* variables; /**< Variables collection */
	uint32_t variablesCount; /**< Number of variables available */
	fiftyoneDegreesCollectionItem itemInfo; /**< Handle for info */
} fiftyoneDegreesIpiCg;

/**
 * An array of all the component graphs and collections available.
 */
FIFTYONE_DEGREES_ARRAY_TYPE(fiftyoneDegreesIpiCg,)

/**
 * Frees all the memory and resources associated with an array of graphs
 * previous created with fiftyoneDegreesIpiGraphCreateFromFile or
 * fiftyoneDegreesIpiGraphCreateFromMemory.
 * @param graphs pointer to the array to be freed
 */
void fiftyoneDegreesIpiGraphFree(fiftyoneDegreesIpiCgArray* graphs);

/**
 * Creates and initializes an array of graphs for the collection where the
 * underlying data set is held in memory.
 * @param collection of fiftyoneDegreesIpiCgInfo records
 * @param reader to the source data
 * @param exception pointer to an exception data structure to be used if an
 * exception occurs. See exceptions.h.
 * @return a pointer to the newly allocated array, or null if the operation
 * was not successful.
 */
EXTERNAL fiftyoneDegreesIpiCgArray* fiftyoneDegreesIpiGraphCreateFromMemory(
	fiftyoneDegreesCollection* collection,
	fiftyoneDegreesMemoryReader* reader,
	fiftyoneDegreesException* exception);

/**
 * Creates and initializes an array of graphs for the collection where the
 * underlying data set is on the file system.
 * @param collection of fiftyoneDegreesIpiCgInfo records
 * @param file for to the source data
 * @param reader pool connected to the file
 * @param config for the collections created for each graph
 * @param exception pointer to an exception data structure to be used if an
 * exception occurs. See exceptions.h.
 * @return a pointer to the newly allocated array, or null if the operation
 * was not successful.
 */
EXTERNAL fiftyoneDegreesIpiCgArray* fiftyoneDegreesIpiGraphCreateFromFile(
	fiftyoneDegreesCollection* collection,
	FILE* file,
	fiftyoneDegreesFilePool* reader,
	const fiftyoneDegreesCollectionConfig config,
	fiftyoneDegreesException* exception);

/**
 * Obtains the profile index for the IP address and component id provided.
 * @param graphs array for each component id and IP version
 * @param componentId of the index required
 * @param address IP address to return a profile index for
 * @param exception pointer to an exception data structure to be used if an
 * exception occurs. See exceptions.h.
 * @return the index of the profile associated with the IP address.
 */
EXTERNAL uint32_t fiftyoneDegreesIpiGraphEvaluate(
	fiftyoneDegreesIpiCgArray* graphs,
	byte componentId,
	fiftyoneDegreesIpAddress address,
	fiftyoneDegreesException* exception);

/**
 * Obtains the profile index for the IP address and component id provided 
 * populating the buffer provided with trace information. Requires the
 * definition FIFTYONE_DEGREES_IPI_GRAPH_TRACE to be present.
 * @param graphs array for each component id and IP version
 * @param componentId of the index required
 * @param address IP address to return a profile index for
 * @param buffer that will be populated with the trace information
 * @param length of the buffer
 * @param exception pointer to an exception data structure to be used if an
 * exception occurs. See exceptions.h.
 * @return the index of the profile associated with the IP address.
 */
EXTERNAL uint32_t fiftyoneDegreesIpiGraphEvaluateTrace(
	fiftyoneDegreesIpiCgArray* graphs,
	byte componentId,
	fiftyoneDegreesIpAddress address,
	char* buffer,
	int const length,
	fiftyoneDegreesException* exception);

/**
 * @}
 */

#endif
