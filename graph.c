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
	byte bitIndex; // Current bit index from high to low in the IP address 
				   // value array
	Exception* ex; // Current exception instance
	uint64_t current; // The value of the current item in the graph
	uint64_t recordIndex; // The current index in the graph collection
	byte skip; // The number of bits left to be skipped
	StringBuilder* sb; // String builder used for trace information
	Item item; // Data for the current item in the graph
} Cursor;

static void traceNewLine(Cursor* cursor) {
	StringBuilderAddChar(cursor->sb, '\r');
	StringBuilderAddChar(cursor->sb, '\n');
}

static void traceBool(Cursor* cursor, const char* method, bool value) {
	StringBuilderAddChar(cursor->sb, '\t');
	StringBuilderAddChars(cursor->sb, method, strlen(method));
	StringBuilderAddChar(cursor->sb, '=');
	StringBuilderAddChar(cursor->sb, value ? '1' : '0');
	traceNewLine(cursor);
}

static void traceInt(Cursor* cursor, const char* method, int value) {
	StringBuilderAddChar(cursor->sb, '\t');
	StringBuilderAddChars(cursor->sb, method, strlen(method));
	StringBuilderAddChar(cursor->sb, '=');
	StringBuilderAddInteger(cursor->sb, value);
	traceNewLine(cursor);
}

static void traceIteration(Cursor* cursor, bool bit) {
	StringBuilderAddChar(cursor->sb, '[');
	StringBuilderAddInteger(cursor->sb, cursor->bitIndex);
	StringBuilderAddChar(cursor->sb, ']');
	StringBuilderAddChar(cursor->sb, '=');
	StringBuilderAddChar(cursor->sb, bit ? '1' : '0');
	StringBuilderAddChar(cursor->sb, ' ');
	StringBuilderAddInteger(cursor->sb, cursor->skip);
	traceNewLine(cursor);
}

#define RESULT "result"
static void traceResult(Cursor* cursor, uint32_t result) {
	traceNewLine(cursor);
	StringBuilderAddChars(cursor->sb, RESULT, sizeof(RESULT) - 1);
	StringBuilderAddChar(cursor->sb, '=');
	StringBuilderAddInteger(cursor->sb, (int)result);
	traceNewLine(cursor);
}

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
	byte bitIndex = 7 - (cursor->bitIndex % 8);
	return (cursor->ip.value[byteIndex] & masks[bitIndex]) != 0;
}

/*
 * Function: extract_u64
 * ---------------------
 *  Extracts an unsigned 64-bit integer from a byte array,
 *  starting from a specified bit index (0-7) in the first byte.
 *
 *  Parameters:
 *    buf: Pointer to an array of bytes containing the bit stream.
 *    bit_index: Bit offset (0-7) within the first byte where the 64-bit integer starts.
 *
 *  Returns:
 *    The extracted unsigned 64-bit integer.
 *
 * Note:
 * The bits are stored in big-endian bit order (i.e. the most significant 
 * bit is encountered first in each byte).
 */
uint64_t extractValue(
	const byte recordSize,
	const byte* buf, 
	unsigned bitIndex) {
	uint64_t result = 0;
	byte byteIndex = 0;
	uint8_t byte = buf[byteIndex];
	for (unsigned i = 0; i < recordSize; i++) {

		// Extract the bit (0 or 1).
		uint8_t bit = (byte >> bitIndex) & 1;

		// Shift the result left and add the bit.
		result = (result << 1) | bit;

		// Reduce the bit index and adjust the byte index if 0.
		if (bitIndex == 0) {
			bitIndex = 7;
			byteIndex++;
			byte = buf[byteIndex];
		}
		else {
			bitIndex--;
		}
	}
	return result;
}

// Moves the cursor to the index in the collection returning the value of the
// record. Uses CgInfo.recordSize to convert the byte array of the record into
// a 64 bit positive integer.
static uint64_t cursorMove(Cursor* cursor, uint64_t recordIndex) {

	// Work out the byte index for the record index and the starting bit index
	// within that byte.
	uint64_t startBitIndex = (recordIndex * cursor->graph->info->recordSize);
	uint64_t byteIndex = startBitIndex / 8;
	byte highBitIndex = 7 - (startBitIndex % 8);

	// Get a pointer to that byte from the collection.
	// TODO change to 64 bit variant.
	byte* ptr = (byte*)cursor->graph->collection->get(
		cursor->graph->collection,
		(uint32_t)byteIndex,
		&cursor->item,
		cursor->ex);

	// Set the record index.
	cursor->recordIndex = recordIndex;

	// Move the bits in the bytes pointed to create the requirement unsigned
	// long.
	cursor->current = extractValue(
		cursor->graph->info->recordSize,
		ptr, 
		highBitIndex);

	// Release the data and then return the current cursor value.
	cursor->item.collection->release(&cursor->item);
	return cursor->current;
}

// Creates a cursor ready for evaluation with the graph and IP address.
static Cursor cursorCreate(
	IpiCg* graph, 
	IpAddress ip, 
	StringBuilder* sb,
	Exception* exception) {
	Cursor cursor = {
		graph,
		ip,
		0,
		exception,
		0,
		0,
		0,
		sb
	};
	DataReset(&cursor.item.data);
	return cursor;
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

// True if the cursor is currently positioned on a leaf and therefore profile 
// index.
static bool getIsProfileIndex(Cursor* cursor) {
	return getValue(cursor) >= cursor->graph->info->graphCount;
}

// The index of the profile associated with the value if this is a leaf value.
// getIsProfileIndex must be called before getting the profile index.
static uint32_t getProfileIndex(Cursor* cursor) {
	return (uint32_t)(getValue(cursor) - cursor->graph->info->graphCount);
}

// True if the cursor value is leaf, otherwise false.
static bool isLeaf(Cursor* cursor) {
	bool result = getIsProfileIndex(cursor);
	traceBool(cursor, "isLeaf", result);
	return result;
}

// True if the cursor value has the zero flag set, otherwise false.
static bool isZeroFlag(Cursor* cursor) {
	bool result = getMemberValue(
		cursor->graph->info->zeroFlag, 
		cursor->current) != 0;
	traceBool(cursor, "isZeroFlag", result);
	return result;
}

// True if the cursor value is a zero leaf.
static bool isZeroLeaf(Cursor* cursor) {
	bool result = isZeroFlag(cursor) && isLeaf(cursor);
	traceBool(cursor, "isZeroLeaf", result);
	return result;
}

// The number of bits to skip for the source if zero is matched.
static byte getZeroSkip(Cursor* cursor) {
	byte result = (byte)(cursor->graph->info->zeroSkip.mask == 0 ?
		1 :
		getMemberValue(cursor->graph->info->zeroSkip, cursor->current) + 1);
	traceInt(cursor, "getZeroSkip", result);
	return result;
}

// True if the cursor value is a one leaf.
static bool isOneLeaf(Cursor* cursor) {
	bool result = isZeroFlag(cursor) == false && isLeaf(cursor);
	traceBool(cursor,"isOneLeaf", result);
	return result;
}

// True if the next index is a one leaf.
static bool isNextOneLeaf(Cursor* cursor) {
	bool result = false;
	uint64_t current = cursor->current;
	cursorMove(cursor, cursor->recordIndex + 1);
	result = isOneLeaf(cursor);
	cursor->recordIndex--;
	cursor->current = current;
	traceBool(cursor,"isNextOneLeaf", result);
	return result;
}

// The number of bits to skip for the source if one is matched.
static byte getOneSkip(Cursor* cursor) {
	byte result = (byte)(cursor->graph->info->oneSkip.mask == 0 ?
		1 :
		getMemberValue(cursor->graph->info->oneSkip, cursor->current) + 1);
	traceInt(cursor, "getOneSkip", result);
	return result;
}

// The number of bits to skip for the source if one is matched against the next
// value.
static byte getNextOneSkip(Cursor* cursor) {
	byte result;
	uint64_t current = cursor->current;
	cursorMove(cursor, cursor->recordIndex + 1);
	result = getOneSkip(cursor);
	cursor->recordIndex--;
	cursor->current = current;
	traceInt(cursor, "getNextOneSkip", result);
	return result;
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
		cursorMove(cursor, cursor->recordIndex + 1);
	}

	// Completed processing the selected zero bit. Return false as no profile
	// index is yet found.
	cursor->bitIndex++;
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
		cursorMove(cursor, cursor->recordIndex + 1);
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
			cursorMove(cursor, cursor->recordIndex + 1);
		}
		cursorMove(cursor, (uint32_t)getValue(cursor));
	}

	// Completed processing the selected one bit. Return false as no profile
	// index is yet found.
	cursor->bitIndex++;
	return false;
}

// Evaluates the cursor until a leaf is found and then returns the profile
// index.
static uint32_t evaluate(Cursor* cursor) {
	bool found = false;
	traceNewLine(cursor);
	cursorMove(cursor, cursor->graph->info->graphIndex);
	do
	{
		if (isBitSet(cursor)) {
			traceIteration(cursor, 1);
			found = selectOne(cursor);
		}
		else {
			traceIteration(cursor, 0);
			found = selectZero(cursor);
		}
	} while (found == false);
	return getProfileIndex(cursor);
}

static uint32_t ipiGraphEvaluate(
	fiftyoneDegreesIpiCgArray* graphs,
	byte componentId,
	fiftyoneDegreesIpAddress address,
	StringBuilder* sb,
	fiftyoneDegreesException* exception) {
	uint32_t profileIndex = 0;
	IpiCg* graph;
	for (uint32_t i = 0; i < graphs->count; i++) {
		graph = &graphs->items[i];
		if (address.type == graph->info->version &&
			componentId == graph->info->componentId) {
			Cursor cursor = cursorCreate(graph, address, sb, exception);
			profileIndex = evaluate(&cursor);
			traceResult(&cursor, profileIndex);
			break;
		}
	}
	return profileIndex;
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

// Graph headers might be duplicated across different graphs. As such the 
// reader passed may not be at the first byte of the graph being created. The
// current reader position is therefore modified to that of the header and then
// reset after the operation.
static Collection* ipiGraphCreateFromMemory(
	CollectionHeader header, 
	void* state) {
	MemoryReader* reader = (MemoryReader*)state;
	byte* current = reader->current;
	reader->current = reader->startByte + header.startPosition;
	Collection* collection = CollectionCreateFromMemory(
		(MemoryReader*)state,
		header);
	reader->current = current;
	return collection;
}

static IpiCgArray* ipiGraphCreate(
	Collection* collection,
	collectionCreate collectionCreate,
	void* state,
	Exception* exception) {
	IpiCgArray* graphs;

	// Create the array for each of the graphs.
	uint32_t count = CollectionGetCount(collection);
	FIFTYONE_DEGREES_ARRAY_CREATE(IpiCg, graphs, count); 
	if (graphs == NULL) {
		EXCEPTION_SET(INSUFFICIENT_MEMORY);
		return NULL;
	}

	for (uint32_t i = 0; i < count; i++) {
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
		// TODO create collections that support 64 bit sizes.
		CollectionHeader header;
		header.count = 0;
		header.length = (uint32_t)graphs->items[i].info->graphLength;
		header.startPosition = (uint32_t)graphs->items[i].info->graphStartPosition;
		graphs->items[i].collection = collectionCreate(
			header,
			state);
		if (graphs->items[i].collection == NULL) {
			EXCEPTION_SET(CORRUPT_DATA);
			fiftyoneDegreesIpiGraphFree(graphs);
			return NULL;
		}
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
	StringBuilder sb = { NULL, 0 };
	return ipiGraphEvaluate(graphs, componentId, address, &sb, exception);
}

uint32_t fiftyoneDegreesIpiGraphEvaluateTrace(
	fiftyoneDegreesIpiCgArray* graphs,
	byte componentId,
	fiftyoneDegreesIpAddress address,
	char* buffer,
	int const length,
	fiftyoneDegreesException* exception) {
	StringBuilder sb = { buffer, length };
	uint32_t result = ipiGraphEvaluate(
		graphs, 
		componentId, 
		address, 
		StringBuilderInit(&sb),
		exception);
	StringBuilderAddChar(&sb, '\0');
	return result;
}