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
MAP_TYPE(IpiCgMemberValue)
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

// Structure for the variables.
#pragma pack(push, 1)
typedef struct variable_t {
	uint32_t startIndex; // Start index in the values collection.
	byte length; // Number of bits from high to low to compare
	union {
		uint64_t value;  // Bits for the variable
		byte bytes[sizeof(uint64_t)]; // Array of 8 bytes
	};
} Variable;
#pragma pack(pop)

// Cursor used to traverse the graph for each of the bits in the IP address.
typedef struct cursor_t {
	IpiCg* const graph; // Graph the cursor is working with
	IpAddress const ip; // The IP address source
	byte bitIndex; // Current bit index from high to low in the IP address 
				   // value array
	Exception* ex; // Current exception instance
	uint64_t current; // The value of the current item in the graph
	uint32_t index; // The current index in the graph values collection
	uint32_t previous; // The previous index in the graph values collection
	Variable variable; // The current variable that relates to the record index
	StringBuilder* sb; // String builder used for trace information
	Item item; // Data for the current item in the graph
} Cursor;

#ifdef FIFTYONE_DEGREES_IPI_GRAPH_TRACE
#define TRACE_BOOL(c,m,v) traceBool(c,m,v);
#define TRACE_INT(c,m,v) traceInt(c,m,v);
#define TRACE_ITERATION(c,b) traceIteration(c,b);
#else
#define TRACE_BOOL(c,m,v)
#define TRACE_INT(c,m,v)
#define TRACE_ITERATION(c,b)
#endif

// Forward declaration.
static uint32_t getValue(Cursor* cursor);

static void traceNewLine(Cursor* cursor) {
	StringBuilderAddChar(cursor->sb, '\r');
	StringBuilderAddChar(cursor->sb, '\n');
}

#define TRACE_TRUE "true"
#define TRACE_FALSE "false"
static void traceBool(Cursor* cursor, const char* method, bool value) {
	StringBuilderAddChar(cursor->sb, '\t');
	StringBuilderAddChars(cursor->sb, method, strlen(method));
	StringBuilderAddChar(cursor->sb, '=');
	if (value) {
		StringBuilderAddChars(cursor->sb, TRACE_TRUE, sizeof(TRACE_TRUE) - 1);
	}
	else {
		StringBuilderAddChars(
			cursor->sb,
			TRACE_FALSE,
			sizeof(TRACE_FALSE) - 1);
	}
	traceNewLine(cursor);
}

static void traceInt(Cursor* cursor, const char* method, int64_t value) {
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
	StringBuilderAddInteger(cursor->sb, cursor->index);
	StringBuilderAddChar(cursor->sb, ' ');
	traceNewLine(cursor);
	getValue(cursor);
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

// True if all the bytes of the address have been consumed.
static bool isExhausted(Cursor* cursor) {
	byte byteIndex = cursor->bitIndex / 8;
	return byteIndex >= sizeof(cursor->ip.value);
}

// Gets the bit for the given bit index in the IP address.
static bool getIpBitForIndex(Cursor* cursor, byte ipBitIndex) {
	Exception* exception = cursor->ex;
	byte byteIndex = ipBitIndex / 8;
	byte bitIndex = 7 - (ipBitIndex % 8);
	if (byteIndex >= cursor->ip.length) {
		EXCEPTION_SET(FIFTYONE_DEGREES_STATUS_CORRUPT_DATA);
		return 0;
	}
	return (cursor->ip.value[byteIndex] & masks[bitIndex]) != 0;
}

// Gets the bit for the given bit index of the variable value.
static bool getVariableBitForIndex(Cursor* cursor, byte varBitIndex) {
	Exception* exception = cursor->ex;
	byte byteIndex = varBitIndex / 8;
	byte bitIndex = 7 - (varBitIndex % 8);
	if (byteIndex >= sizeof(cursor->variable.bytes)) {
		EXCEPTION_SET(FIFTYONE_DEGREES_STATUS_CORRUPT_DATA);
		return 0;
	}
	return (cursor->variable.bytes[byteIndex] & masks[bitIndex]) != 0;
}

// Comparer used to determine if the selected variable is higher or lower than
// the target.
static int setVariableComparer(
	void* state,
	Item* item,
	long curIndex,
	Exception* exception) {
	Variable* variable = (Variable*)item->data.ptr;
	Cursor* cursor = (Cursor*)state;
	
	// Store a copy of the variable in the cursor to avoid needing to fetch it
	// again should it prove to be the correct result.
	cursor->variable = *variable;
	
	return variable->startIndex - cursor->index;
}

// Sets the cursor variable to the correct settings for the current value 
// record index. Uses the binary search feature of the collection.
static void setVariable(Cursor* cursor) {
	Exception* exception = cursor->ex;

	// Use binary search to find the index for the variable. The comparer 
	// records the last variable checked the cursor will have the correct
	// variable after the search operation.
	uint32_t index = CollectionBinarySearch(
		cursor->graph->variables,
		&cursor->item,
		0,
		cursor->graph->variables->count - 1,
		(void*)cursor,
		setVariableComparer,
		cursor->ex);

	// Validate that the variable set has a start index equal to or grater than
	// the one required.
	if (cursor->variable.startIndex < cursor->index) {
		EXCEPTION_SET(FIFTYONE_DEGREES_STATUS_CORRUPT_DATA);
		return;
	}

	// Validate that the next variable has a higher start index than the one
	// found. If not then set an exception as the data structure has become
	// corrupt.
	if (index < CollectionGetCount(cursor->graph->variables)) {
		Variable next = *(Variable*)cursor->graph->variables->get(
			cursor->graph->variables,
			index + 1,
			&cursor->item,
			cursor->ex);
		COLLECTION_RELEASE(cursor->graph->variables, &cursor->item);
		if (cursor->index > next.startIndex) {
			EXCEPTION_SET(FIFTYONE_DEGREES_STATUS_CORRUPT_DATA);
			return;
		}
	}
}

/*
 * Function: extractValue
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
	const uint16_t recordSize,
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
static uint64_t cursorMove(Cursor* cursor, uint32_t recordIndex) {

	Exception* exception = cursor->ex;

	// Work out the byte index for the record index and the starting bit index
	// within that byte.
	uint64_t startBitIndex = (
		recordIndex * 
		cursor->graph->info->value.recordSize);
	uint64_t byteIndex = startBitIndex / 8;
	byte highBitIndex = 7 - (startBitIndex % 8);

	// Get a pointer to that byte from the collection.
	byte* ptr = (byte*)cursor->graph->values->get(
		cursor->graph->values,
		(uint32_t)byteIndex,
		&cursor->item,
		cursor->ex);
	if (EXCEPTION_FAILED) return 0;

	// Set the record index.
	cursor->index = recordIndex;

	// Move the bits in the bytes pointed to create the requirement unsigned
	// long.
	cursor->current = extractValue(
		cursor->graph->info->value.recordSize,
		ptr, 
		highBitIndex);

	// Release the data. 
	cursor->item.collection->release(&cursor->item);

	// Set the correct variable to use for any compare operations.
	setVariable(cursor);
	if (EXCEPTION_FAILED) return 0;

	// Then return the current cursor value.
	return cursor->current;
}

// Creates a cursor ready for evaluation with the graph and IP address.
static Cursor cursorCreate(
	IpiCg* graph, 
	IpAddress ip, 
	StringBuilder* sb,
	Exception* exception) {
	Cursor cursor = { graph, ip };
	cursor.ex = exception;
	cursor.sb = sb;
	cursor.variable.length = 0;
	cursor.variable.startIndex = 0;
	cursor.current = 0;
	cursor.index = 0;
	DataReset(&cursor.item.data);
	return cursor;
}

// The IpType for the component graph.
static IpType getIpTypeFromGraph(IpiCgInfo* info) {
	return getIpTypeFromVersion(info->version);
}

// Manipulates the source using the mask and shift parameters of the member.
static uint32_t getMemberValue(IpiCgMember member, uint64_t source) {
	return (uint32_t)(source & member.mask) >> member.shift;
}

// Returns the value of the current item.
static uint32_t getValue(Cursor* cursor) {
	uint32_t result = getMemberValue(
		cursor->graph->info->value.value, 
		cursor->current);
	TRACE_INT(cursor, "getValue", result);
	return result;
}

// True if the cursor is currently positioned on a leaf and therefore profile 
// index.
static bool getIsProfileIndex(Cursor* cursor) {
	bool result = getValue(cursor) >= 
		cursor->graph->info->value.collection.count;
	TRACE_BOOL(cursor, "getIsProfileIndex", result);
	return result;
}

// The index of the profile associated with the value if this is a leaf value.
// getIsProfileIndex must be called before getting the profile index.
static uint32_t getProfileIndex(Cursor* cursor) {
	uint32_t result = (uint32_t)(
		getValue(cursor) - cursor->graph->info->value.collection.count);
	TRACE_INT(cursor, "getProfileIndex", result);
	return result;
}

// True if the cursor value is leaf, otherwise false.
static bool isLeaf(Cursor* cursor) {
	bool result = getIsProfileIndex(cursor);
	TRACE_BOOL(cursor, "isLeaf", result);
	return result;
}

// True if the cursor value has the zero flag set, otherwise false.
static bool isZeroFlag(Cursor* cursor) {
	bool result = getMemberValue(
		cursor->graph->info->value.zeroFlag, 
		cursor->current) != 0;
	TRACE_BOOL(cursor, "isZeroFlag", result);
	return result;
}

// True if the cursor value is a zero leaf.
static bool isZeroLeaf(Cursor* cursor) {
	bool result = isZeroFlag(cursor) && isLeaf(cursor);
	TRACE_BOOL(cursor, "isZeroLeaf", result);
	return result;
}

// True if the cursor value is a one leaf.
static bool isOneLeaf(Cursor* cursor) {
	bool result = isZeroFlag(cursor) == false && isLeaf(cursor);
	TRACE_BOOL(cursor,"isOneLeaf", result);
	return result;
}

// True if the next index is a one leaf.
static bool isNextOneLeaf(Cursor* cursor) {
	Exception* exception = cursor->ex;
	bool result = false;
	uint64_t current = cursor->current;
	cursorMove(cursor, cursor->index + 1);
	if (EXCEPTION_FAILED) return false;
	result = isOneLeaf(cursor);
	cursor->index--;
	cursor->current = current;
	TRACE_BOOL(cursor,"isNextOneLeaf", result);
	return result;
}

/// <summary>
/// Moves the cursor for a lower entry.
/// </summary>
/// <returns>
/// True if a leaf has been found and getProfileIndex can be used to return a 
/// result.
/// </returns>
static bool selectLower(Cursor* cursor) {
	Exception* exception = cursor->ex;

	// Check the current entry to see if it is a zero leaf.
	if (isZeroLeaf(cursor)) {
		return true;
	}

	if (isZeroFlag(cursor)) {
		// If the zero flag is set then the next zero entry is not the next
		// consecutive entry but the index that this now points to.
		cursorMove(cursor, (uint32_t)getValue(cursor));
		if (EXCEPTION_FAILED) return false;
	}
	else {
		// If the zero flag is not set then the next zero entry is the next
		// entry in the collection.
		cursorMove(cursor, cursor->index + 1);
		if (EXCEPTION_FAILED) return false;
	}

	// Return false as no profile index is yet found.
	return false;
}

/// <summary>
/// Moves the cursor for an equals.
/// </summary>
/// <returns>
/// True if a leaf has been found and getProfileIndex can be used to return a 
/// result.
/// </returns>
static bool selectMatched(Cursor* cursor) {
	Exception* exception = cursor->ex;

	// Check the current entry to see if it is a matched leaf.
	if (isOneLeaf(cursor)) {
		return true;
	}

	// An additional check is needed for the data structure as the current
	// entry might relate to the lower entry. If this is the case then the next
	// entry that might contain the equal leaf.
	if (isZeroFlag(cursor) && isNextOneLeaf(cursor)) {
		cursorMove(cursor, cursor->index + 1);
		if (EXCEPTION_FAILED) return false;
		return true;
	}

	// No leaf has been found so move the cursor to the next record.
	// Check to see if the lower flag is set meaning the entry needs to be
	// skipped over.
	if (isZeroFlag(cursor)) {
		cursorMove(cursor, cursor->index + 1);
		if (EXCEPTION_FAILED) return false;
	}

	// Move to the matched entry indicated.
	cursorMove(cursor, (uint32_t)getValue(cursor));
	if (EXCEPTION_FAILED) return false;

	// Completed processing the selected equals entry. Return false as no 
	// profile index is yet found.
	return false;
}

/// <summary>
/// Moves the cursor to the previous entry, selects the equals option, and then
/// all the lower options until a leaf is found.
/// </summary>
/// <returns>
/// True if a leaf has been found and getProfileIndex can be used to return a 
/// result.
/// </returns>
static bool selectHigher(Cursor* cursor) {
	Exception* exception = cursor->ex;

	// Move back to the previous entry.
	cursorMove(cursor, cursor->previous);
	if (EXCEPTION_FAILED) return true;

	// Check for the lower flag and if present move to the next entry which 
	// will be for equals.
	if (isZeroFlag(cursor)) {
		cursorMove(cursor, cursor->index + 1);
		if (EXCEPTION_FAILED) return true;
	}

	// Follow the equals entry.
	cursorMove(cursor, (uint32_t)getValue(cursor));
	if (EXCEPTION_FAILED) return true;

	// Follow the lower entries until a leaf is found.
	while (isLeaf(cursor) == false) {

		// If this entry is a zero flag then follow it, otherwise move to the
		// next entry.
		if (isZeroFlag(cursor)) {
			cursorMove(cursor, (uint32_t)getValue(cursor));
			if (EXCEPTION_FAILED) return true;
		}
		else {
			cursorMove(cursor, cursor->index + 1);
			if (EXCEPTION_FAILED) return true;
		}
	}

	return true;
}

// Compares the current variable bits to the bits in the IP address. Returns
// If the next bits in the IP address;
// -1 = are lower then -1 is returned. The caller needs to move to the lower
// record.
// 0 = match then 0 is returned. The caller needs to move to the equals to
// record.
// 1 = are greater then 1 is returned. The caller needs to move to the previous
// record, take the equals to route, and continue down the lower records until
// the lowest leaf is found.
static int compareToVariable(Cursor* cursor) {
	byte ipBitIndex = cursor->bitIndex;

	// Record the initial index as we might need to return to this later.
	uint32_t initial = cursor->index;

	// If this is a zero flag then we'll need to move to the next record for
	// comparison.
	if (isZeroFlag(cursor)) {
		cursorMove(cursor, cursor->index++);
	}

	for (byte i = 0; i < cursor->variable.length; i++) {

		// Get the bit from the IP address.
		bool ipBit = getIpBitForIndex(cursor, ipBitIndex);

		// Get the bit from the variable.
		bool varBit = getVariableBitForIndex(cursor, i);

		// If the bits are not equal return -1 or 1.
		if (ipBit != varBit)
		{
			return ipBit == false ? -1 : 1;
		}
	}

	// All the bits are equal return 0.
	return 0;
}

// Evaluates the cursor until a leaf is found and then returns the profile
// index.
static uint32_t evaluate(Cursor* cursor) {
	Exception* exception = cursor->ex;
	bool found = false;
	traceNewLine(cursor);
	cursorMove(cursor, cursor->graph->info->graphIndex);
	do
	{
		// Record the previous index as this might be needed should be bits
		// found be greater than the next entry.
		cursor->previous = cursor->index;

		int result = compareToVariable(cursor);
		TRACE_ITERATION(cursor, result);
		switch (result) {
		case -1:
			found = selectLower(cursor);
			if (EXCEPTION_FAILED) return 0;
			break;
		case 0:
			found = selectMatched(cursor);
			if (EXCEPTION_FAILED) return 0;
			break;
		case 1:
			found = selectHigher(cursor);
			if (EXCEPTION_FAILED) return 0;
			break;
		}
	} while (found == false && isExhausted(cursor) == false);
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
			if (EXCEPTION_FAILED) return 0;
			traceResult(&cursor, profileIndex);
			break;
		}
	}
	return profileIndex;
}

// Graph headers might be duplicated across different graphs. As such the 
// reader passed may not be at the first byte of the graph being created. The
// current reader position is therefore modified to that of the header and then
// reset after the operation.
static Collection* ipiGraphCreateFromFile(
	CollectionHeader header,
	void* state) {
	FileCollection* s = (FileCollection*)state;
	// TODO Apply the same logic to the file reader as the memory reader.
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
		graphs->items[i].values = NULL;
		graphs->items[i].variables = NULL;

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

		// Create the collection for the values that form the graph.
		CollectionHeader headerValues;

		// Must be zero as the count is not measured in bytes.
		headerValues.count = 0; 
		headerValues.length = 
			graphs->items[i].info->value.collection.length;
		headerValues.startPosition = 
			graphs->items[i].info->value.collection.startPosition;
		graphs->items[i].values = collectionCreate(
			headerValues,
			state);
		if (graphs->items[i].values == NULL) {
			EXCEPTION_SET(CORRUPT_DATA);
			fiftyoneDegreesIpiGraphFree(graphs);
			return NULL;
		}

		// Create the collection for the variables that are used to evaluate
		// the result of each value record.
		CollectionHeader headerVariables;
		headerVariables.count = graphs->items[i].info->variable.count;
		headerVariables.length =
			graphs->items[i].info->variable.length;
		headerVariables.startPosition =
			graphs->items[i].info->variable.startPosition;
		graphs->items[i].variables = collectionCreate(
			headerVariables,
			state);
		if (graphs->items[i].variables == NULL) {
			EXCEPTION_SET(CORRUPT_DATA);
			fiftyoneDegreesIpiGraphFree(graphs);
			return NULL;
		}
	}

	return graphs;
}

void fiftyoneDegreesIpiGraphFree(fiftyoneDegreesIpiCgArray* graphs) {
	for (uint32_t i = 0; i < graphs->count; i++) {
		graphs->items[i].itemInfo.collection->release(
			&graphs->items[i].itemInfo);
		FIFTYONE_DEGREES_COLLECTION_FREE(graphs->items[i].values);
		FIFTYONE_DEGREES_COLLECTION_FREE(graphs->items[i].variables);
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