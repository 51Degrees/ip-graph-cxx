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

#include "graph.h"
#include "../common-cxx/fiftyone.h"

MAP_TYPE(IpiCg)
MAP_TYPE(IpiCgArray)
MAP_TYPE(IpiCgMember)
MAP_TYPE(IpiCgInfo)
MAP_TYPE(Collection)

/**
 * MASKS TO OBTAIN BITS FROM IP ADDRESS
 */

byte masks[8] = {
	1ULL,
	1ULL << 1,
	1ULL << 2,
	1ULL << 3,
	1ULL << 4,
	1ULL << 5,
	1ULL << 6,
	1ULL << 7
};

/**
 * DATA STRUCTURES
 */

// State used when creating file collections for each of the graphs.
typedef struct file_collection_t {
	FILE* file;
	fiftyoneDegreesFilePool* reader;
	const fiftyoneDegreesCollectionConfig config;
} FileCollection;

// Function used to create the collection for each of the graphs.
typedef Collection*(*collectionCreate)(CollectionHeader header, void* state);

// Cursor used to traverse the graph for each of the bits in the IP address.
typedef struct cursor_t {
	IpiCg* const graph; // Graph the cursor is working with
	IpAddress const ip; // The IP address source
	byte bitIndex; // Bit index from high to low in the IP address value array
	Exception* ex; // Current exception instance
	uint64_t current; // The value of the current item in the graph
	uint32_t index; // The current index in the collection
	byte skip; // The number of bits left to be skipped
	Item item; // Data for the current item in the graph
} Cursor;

// The IpType for the version byte.
static IpType getIpTypeFromVersion(byte version) {
	switch (version)
	{
	case 4: return IP_TYPE_IPV4;
	case 6: return IP_TYPE_IPV6;
	default: return IP_TYPE_INVALID;
	}
}

// True if the bit at the current cursor->bitIndex is 1, otherwise 0.
static bool isBitSet(Cursor* cursor) {
	byte byteIndex = cursor->bitIndex / 8;
	byte bitIndex = cursor->bitIndex % 8;
	return (cursor->ip.value[byteIndex] & masks[bitIndex]) != 0;
}

// Creates a cursor ready for evaluation with the graph and IP address.
static Cursor cursorCreate(IpiCg* graph, IpAddress ip, Exception* exception) {
	Cursor cursor = {
		graph,
		ip,
		graph->startBitIndex,
		exception,
		0,
		0,
		0
	};
	DataReset(&cursor.item.data);
	return cursor;
}

// Moves the cursor to the index in the collection returning the value of the
// record. Uses CgInfo.recordSize to convert the byte array of the record into
// a 64 bit positive integer.
static uint64_t cursorMove(Cursor* cursor, uint32_t index) {
	byte* ptr = (byte*)cursor->graph->collection->get(
		cursor->graph->collection,
		index,
		&cursor->item,
		cursor->ex);
	cursor->index = index;
	cursor->current = 0;
	for (uint32_t i = 0; i < cursor->graph->info->recordSize; i++) {
		cursor->current |= ptr[i] <<
			((i - cursor->graph->info->recordSize) * 8);
	}
	cursor->item.collection->release(&cursor->item);
	return cursor->current;
}

// The IpType for the component graph.
static IpType getIpTypeFromGraph(IpiCgInfo* info) {
	return getIpTypeFromVersion(info->version);
}

// Manipulates the source using the mask and shift parameters of the member.
static uint64_t getMemberValue(IpiCgMember member, uint64_t source) {
	return (source & member.mask) >> member.shift;
}

// Returns the value of the current item.
static uint64_t getValue(Cursor* cursor) {
	return getMemberValue(cursor->graph->info->value, cursor->current);
}

// The index of the profile associated with the value if this is a leaf value.
// A return value must be positive to relate to a profile, if negative then the
// value is not a leaf.
static uint32_t getProfileIndex(Cursor* cursor) {
	return (uint32_t)(
		getValue(cursor) - 
		CollectionGetCount(cursor->graph->collection));
}

// True if the cursor value is leaf, otherwise false.
static bool isLeaf(Cursor* cursor) {
	return getProfileIndex(cursor) >= 0;
}

// True if the cursor value has the zero flag set, otherwise false.
static bool isZeroFlag(Cursor* cursor) {
	return getMemberValue(cursor->graph->info->zeroFlag, cursor->current) != 0;
}

// True if the cursor value is a zero leaf.
static bool isZeroLeaf(Cursor* cursor) {
	return isZeroFlag(cursor) && isLeaf(cursor);
}

// The number of bits to skip for the source if zero is matched.
static byte getZeroSkip(Cursor* cursor) {
	return (byte)(cursor->graph->info->zeroSkip.mask == 0 ?
		0 :
		getMemberValue(cursor->graph->info->zeroSkip, cursor->current) + 1);
}

// True if the cursor value is a one leaf.
static bool isOneLeaf(Cursor* cursor) {
	return isZeroFlag(cursor) == false && isLeaf(cursor);
}

// True if the next index is a one leaf.
static bool isNextOneLeaf(Cursor* cursor) {
	bool result = false;
	uint64_t current = cursor->current;
	cursorMove(cursor, cursor->index + 1);
	result = isOneLeaf(cursor);
	cursor->index--;
	cursor->current = current;
	return result;
}

// The number of bits to skip for the source if one is matched.
static byte getOneSkip(Cursor* cursor) {
	return (byte)(cursor->graph->info->oneSkip.mask == 0 ?
		0 :
		getMemberValue(cursor->graph->info->oneSkip, cursor->current) + 1);
}

// The number of bits to skip for the source if one is matched against the next
// value.
static byte getNextOneSkip(Cursor* cursor) {
	byte result;
	uint64_t current = cursor->current;
	cursorMove(cursor, cursor->index + 1);
	result = getOneSkip(cursor);
	cursor->index--;
	cursor->current = current;
	return result;
}

// Calculates the bit index in the IP address that evaluation should start at.
static byte graphStartBitIndex(IpiCg* graph) {
	switch (getIpTypeFromGraph(graph->info)) {
	case IP_TYPE_IPV4:
		return 31;
	case IP_TYPE_IPV6:
		return 127;
	}
	return 0;
}

/// <summary>
/// Moves the cursor for a zero bit.
/// </summary>
/// <returns>
/// True if a leaf has been found and getProfileIndex can be used to return a 
/// result.
/// </returns>
static bool selectZero(Cursor* cursor) {

	// Check the current node for the bit to see if it is a zero leaf.
	if (isZeroLeaf(cursor)) {
		return true;
	}

	// If all the bits have finished being skipped then check the current node
	// to determine how many bits can be skipped by the next node.
	if (cursor->skip == 0) {
		cursor->skip = getZeroSkip(cursor);
	}

	// Decrease the skip counter and if the current node needs to be updated
	// move to it.
	cursor->skip--;
	if (cursor->skip == 0) {
		cursorMove(cursor, cursor->index + 1);
	}

	// Completed processing the selected zero bit. Return false as no profile
	// index is yet found.
	cursor->bitIndex--;
	return false;
}

/// <summary>
/// Moves the cursor for a one bit.
/// </summary>
/// <returns>
/// True if a leaf has been found and getProfileIndex can be used to return a 
/// result.
/// </returns>
static bool selectOne(Cursor* cursor) {

	// Check the current node for the bit to see if it is a one leaf.
	if (isOneLeaf(cursor)) {
		return true;
	}

	// An additional check is needed for the one data structure as the current
	// node might relate to the zero leaf. If this is the case then it's 
	// actually the next node that might contain the one leaf.
	if (isZeroLeaf(cursor) && isNextOneLeaf(cursor)) {
		cursorMove(cursor, cursor->index + 1);
		return true;
	}

	// If all the bits have finished being skipped then check the current node
	// to determine how many bits can be skipped by the next node. This
	// involves checking if the current node is the zero leaf and using the
	// next node if this is the case.
	if (cursor->skip == 0)
	{
		if (isZeroLeaf(cursor)) {
			cursor->skip = getNextOneSkip(cursor);
		}
		else {
			cursor->skip = getOneSkip(cursor);
		}
	}

	// Decrease the skip counter and if the current node needs to be updated 
	// move to it. This involves moving to the next node if the current node is
	// the zero leaf, and then using the value of that node as the index of the
	// next one node.
	cursor->skip--;
	if (cursor->skip == 0)
	{
		if (isZeroLeaf(cursor)) {
			cursorMove(cursor, cursor->index + 1);
		}
		cursorMove(cursor, (uint32_t)getValue(cursor));
	}

	// Completed processing the selected one bit. Return false as no profile
	// index is yet found.
	cursor->bitIndex--;
	return false;
}

// Evaluates the cursor until a profile index is found and then returns the
// profile index.
static uint32_t evaluate(Cursor* cursor) {
	bool found = false;
	do
	{
		if (isBitSet(cursor)) {
			found = selectOne(cursor);
		}
		else {
			found = selectZero(cursor);
		}
	} while (found == false);
	return getProfileIndex(cursor);
}

static Collection* ipiGraphCreateFromFile(
	CollectionHeader header,
	void* state) {
	FileCollection* s = (FileCollection*)state;
	return CollectionCreateFromFile(
		s->file,
		s->reader,
		&s->config,
		header, 
		CollectionReadFileFixed);
}

static Collection* ipiGraphCreateFromMemory(
	CollectionHeader header, 
	void* state) {
	return CollectionCreateFromMemory((MemoryReader*)state, header);
}

static IpiCgArray* ipiGraphCreate(
	Collection* collection,
	collectionCreate collectionCreate,
	void* state,
	Exception* exception) {
	IpiCgArray* graphs;

	// Create the array for each of the graphs.
	uint32_t size = CollectionGetCount(collection);
	FIFTYONE_DEGREES_ARRAY_CREATE(IpiCg, graphs, size); 
	if (graphs == NULL) {
		EXCEPTION_SET(INSUFFICIENT_MEMORY);
		return NULL;
	}

	for (uint32_t i = 0; i < size; i++) {
		graphs->items[i].collection = NULL;

		// Get the information from the collection provided.
		DataReset(&graphs->items[i].itemInfo.data);
		graphs->items[i].info = (IpiCgInfo*)collection->get(
			collection, 
			i,
			&graphs->items[i].itemInfo,
			exception);
		if (EXCEPTION_OKAY == false) {
			fiftyoneDegreesIpiGraphFree(graphs);
			return NULL;
		}
		graphs->count++;

		// Create a collection for the graph.
		graphs->items[i].collection = collectionCreate(
			graphs->items[i].info->header, 
			state);
		if (graphs->items[i].collection == NULL) {
			// TODO check status code.
			EXCEPTION_SET(INSUFFICIENT_MEMORY);
			fiftyoneDegreesIpiGraphFree(graphs);
			return NULL;
		}

		// Finally set the start bit index to avoid checking this for every
		// evaluation.
		graphs->items[i].startBitIndex = graphStartBitIndex(&graphs->items[i]);
	}

	return graphs;
}

void fiftyoneDegreesIpiGraphFree(fiftyoneDegreesIpiCgArray* graphs) {
	for (uint32_t i = 0; i < graphs->count; i++) {
		FIFTYONE_DEGREES_COLLECTION_FREE(graphs->items[i].collection);
		graphs->items[i].itemInfo.collection->release(
			&graphs->items[i].itemInfo);
	}
	Free(graphs);
}

fiftyoneDegreesIpiCgArray* fiftyoneDegreesIpiGraphCreateFromMemory(
	fiftyoneDegreesCollection* collection,
	fiftyoneDegreesMemoryReader* reader,
	fiftyoneDegreesException* exception) {
	return ipiGraphCreate(
		collection,
		ipiGraphCreateFromMemory,
		(void*)reader,
		exception);
}

fiftyoneDegreesIpiCgArray* fiftyoneDegreesIpiGraphCreateFromFile(
	fiftyoneDegreesCollection* collection,
	FILE* file,
	fiftyoneDegreesFilePool* reader,
	const fiftyoneDegreesCollectionConfig config,
	fiftyoneDegreesException* exception) {
	FileCollection state = {
		file,
		reader,
		config
	};
	return ipiGraphCreate(
		collection,
		ipiGraphCreateFromFile,
		(void*)&state,
		exception);
}

uint32_t fiftyoneDegreesIpiGraphEvaluate(
	fiftyoneDegreesIpiCgArray* graphs,
	byte componentId,
	fiftyoneDegreesIpAddress address,
	fiftyoneDegreesException* exception) {
	uint32_t profileIndex = 0;
	IpiCg* graph;
	for (uint32_t i = 0; graphs->count; i++) {
		graph = &graphs->items[i];
		if (address.type == graph->info->version &&
			componentId == graph->info->componentId) {
			Cursor cursor = cursorCreate(graph, address, exception);
			profileIndex = evaluate(&cursor);
			break;
		}
	}
	return profileIndex;
}