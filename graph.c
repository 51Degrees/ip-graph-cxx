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
 * RESULTS FROM COMPARE OPERATIONS - THE IP ADDRESS SEGMENT IS;
 */
typedef enum {
	UNUSED,
	LESS_THAN_LOW,
	EQUAL_LOW,
	INBETWEEN,
	EQUAL_HIGH,
	GREATER_THAN_HIGH
} CompareResult;

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
	uint32_t startIndex; // Inclusive start index in the values collection.
	uint32_t endIndex; // Inclusive end index in the values collection.
	byte length; // Length of the low and high members
	union {
		uint32_t low; // Bits for the low variable
		byte lowBytes[sizeof(uint32_t)]; // Array of 4 bytes
	};
	union {
		uint32_t high; // Bits for the high variable
		byte highBytes[sizeof(uint32_t)]; // Array of 4 bytes
	};
} Variable;
#pragma pack(pop)

// Cursor used to traverse the graph for each of the bits in the IP address.
typedef struct cursor_t {
	IpiCg* const graph; // Graph the cursor is working with
	IpAddress const ip; // The IP address source
	uint32_t ipValue; // The value that should be compared to the variable
	byte bitIndex; // Current bit index from high to low in the IP address 
				   // value array
	uint64_t current; // The value of the current item in the graph
	uint32_t index; // The current index in the graph values collection
	uint32_t previousHighIndex; // The index of the last high index
	Variable variable; // The current variable that relates to the record index
	byte variableSet; // True after the first time the variable is set
	CompareResult compareResult; // Result of comparing the current bits to the
								 // variable value
	Item item; // Data for the current item in the graph
	StringBuilder* sb; // String builder used for trace information
	Exception* ex; // Current exception instance
} Cursor;

#ifdef FIFTYONE_DEGREES_IPI_GRAPH_TRACE
#define TRACE_BOOL(c,m,v) traceBool(c,m,v);
#define TRACE_INT(c,m,v) traceInt(c,m,v);
#define TRACE_COMPARE(c) traceCompare(c);
#define TRACE_LABEL(c,m) traceLabel(c,m);
#define TRACE_RESULT(c,r) traceResult(c,r);
#else
// TODO
#endif

static void traceNewLine(Cursor* cursor) {
	StringBuilderAddChar(cursor->sb, '\r');
	StringBuilderAddChar(cursor->sb, '\n');
}

static void traceLabel(Cursor* cursor, const char* label) {
	StringBuilderAddChar(cursor->sb, '\t');
	StringBuilderAddChars(cursor->sb, label, strlen(label));
	traceNewLine(cursor);
}

// Returns the bits from high to low order.
static void uintToBinary(Cursor* cursor, uint64_t number, int length) {
	int count = 0;
	for (int i = length - 1; i >= 0; i--)
	{
		int bit = (number & (((uint64_t)1) << i)) != 0;
		StringBuilderAddChar(cursor->sb, bit ? '1' : '0');
		count++;
		if (count % 4 == 0 && i > 0) {
			StringBuilderAddChar(cursor->sb, ' ');
		}
	}
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

#define CLTL "LESS_THAN_LOW"
#define CEL "EQUAL_LOW"
#define CIB "INBETWEEN"
#define CEH "EQUAL_HIGH"
#define CGTH "GREATER_THAN_HIGH"
#define IP "IP:" // IP value
#define LV "LV:" // Low Value
#define HV "HV:" // High Value
#define VS "VS:" // Variable Start index
#define CI "CI:" // Cursor Index
#define VE "VE:" // Variable End index
static void traceCompare(Cursor* cursor) {
	StringBuilderAddChar(cursor->sb, '[');
	StringBuilderAddInteger(cursor->sb, cursor->bitIndex);
	StringBuilderAddChar(cursor->sb, ']');
	StringBuilderAddChar(cursor->sb, '=');
	switch (cursor->compareResult)
	{
	case LESS_THAN_LOW:
		StringBuilderAddChars(cursor->sb, CLTL, sizeof(CLTL) - 1);
		break;
	case EQUAL_LOW:
		StringBuilderAddChars(cursor->sb, CEL, sizeof(CEL) - 1);
		break;
	case INBETWEEN:
		StringBuilderAddChars(cursor->sb, CIB, sizeof(CIB) - 1);
		break;
	case EQUAL_HIGH:
		StringBuilderAddChars(cursor->sb, CEH, sizeof(CEH) - 1);
		break;
	case GREATER_THAN_HIGH:
		StringBuilderAddChars(cursor->sb, CGTH, sizeof(CGTH) - 1);
		break;
	}
	StringBuilderAddChar(cursor->sb, ' ');
	StringBuilderAddChars(cursor->sb, IP, sizeof(IP) - 1);
	uintToBinary(cursor, cursor->ipValue, cursor->variable.length);
	StringBuilderAddChar(cursor->sb, ' ');
	StringBuilderAddChars(cursor->sb, LV, sizeof(LV) - 1);
	uintToBinary(cursor, cursor->variable.low, cursor->variable.length);
	StringBuilderAddChar(cursor->sb, ' ');
	StringBuilderAddChars(cursor->sb, HV, sizeof(HV) - 1);
	uintToBinary(cursor, cursor->variable.high, cursor->variable.length);
	StringBuilderAddChar(cursor->sb, ' ');
	StringBuilderAddChars(cursor->sb, VS, sizeof(VS) - 1);
	StringBuilderAddInteger(cursor->sb, cursor->variable.startIndex);
	StringBuilderAddChar(cursor->sb, ' ');
	StringBuilderAddChars(cursor->sb, CI, sizeof(CI) - 1);
	StringBuilderAddInteger(cursor->sb, cursor->index);
	StringBuilderAddChar(cursor->sb, ' ');
	StringBuilderAddChars(cursor->sb, VE, sizeof(VE) - 1);
	StringBuilderAddInteger(cursor->sb, cursor->variable.endIndex);
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

// Sets the cursor->ipValue to the bits needed to perform an integer comparison
// operation with the cursor->variable.
static void setIpValue(Cursor* cursor) {
	
	// Reset the IP value ready to include the new bits.
	uint32_t value = 0;

	// Extract cursor->variableLength bits from cursor->bitIndex.
	for (byte i = 0; i < cursor->variable.length; i++) {

		byte currentBitIndex = cursor->bitIndex + i;
		byte byteIndex = currentBitIndex / 8;
		byte bitInByte = currentBitIndex % 8;

		// Shift the current byte so that the target bit is in the LSB, then 
		// mask it.
		byte bit = (cursor->ip.value[byteIndex] >> (7 - bitInByte)) & 1;

		// Shift result left to make room for this new bit, then add it.
		value = (value << 1) | bit;
	}

	cursor->ipValue = value;
}

// True if all the bytes of the address have been consumed.
static bool isExhausted(Cursor* cursor) {
	byte byteIndex = cursor->bitIndex / 8;
	return byteIndex >= sizeof(cursor->ip.value);
}

// Comparer used to determine if the selected variable is higher or lower than
// the target.
static int setVariableComparer(
	Cursor* cursor,
	Item* item,
	long curIndex,
	Exception* exception) {
	Variable* variable = (Variable*)item->data.ptr;

	// Store a copy of the variable in the cursor to avoid needing to fetch it
	// again should it prove to be the required result.
	cursor->variable = *variable;

	// If this variable is within the require range then its the correct one
	// to return.
	if (cursor->index >= variable->startIndex &&
		cursor->index <= variable->endIndex) {
		return 0;
	}

	return variable->startIndex - cursor->index;
}

static uint32_t setVariableSearch(
	fiftyoneDegreesCollection* collection,
	fiftyoneDegreesCollectionItem* item,
	uint32_t lowerIndex,
	uint32_t upperIndex,
	Cursor* cursor,
	fiftyoneDegreesException* exception) {
	uint32_t upper = upperIndex,
		lower = lowerIndex,
		middle = 0;
	int comparisonResult;
	DataReset(&item->data);
	while (lower <= upper) {

		// Get the middle index for the next item to be compared.
		middle = lower + (upper - lower) / 2;

		// Get the item from the collection checking for NULL or an error.
		if (collection->get(collection, middle, item, exception) == NULL ||
			EXCEPTION_OKAY == false) {
			return 0;
		}

		// Perform the binary search using the comparer provided with the item
		// just returned.
		comparisonResult = setVariableComparer(cursor, item, middle, exception);
		if (EXCEPTION_OKAY == false) {
			return 0;
		}

		if (comparisonResult == 0) {
			return middle;
		}
		else if (comparisonResult > 0) {
			if (middle) { // guard against underflow of unsigned type
				upper = middle - 1;
			}
			else {
				lower += 1; // break once iteration finishes
			}
		}
		else {
			lower = middle + 1;
		}

		COLLECTION_RELEASE(collection, item);
	}

	// The item could not be found so return the index of the variable that
	// covers the range required.
	return middle;
}

// Sets the cursor variable to the correct settings for the current value 
// record index. Uses the binary search feature of the collection.
static void setVariable(Cursor* cursor) {
	Exception* exception = cursor->ex;

	// Check that the current variable is valid and only move if not.
	if (cursor->variableSet == true &&
		cursor->index >= cursor->variable.startIndex &&
		cursor->index <= cursor->variable.endIndex) {
		return;
	}

	// Use binary search to find the index for the variable. The comparer 
	// records the last variable checked the cursor will have the correct
	// variable after the search operation.
	uint32_t index = setVariableSearch(
		cursor->graph->variables,
		&cursor->item,
		0,
		cursor->graph->variablesCount - 1,
		cursor,
		cursor->ex);

	// Validate that the variable set has a start index equal to or greater
	// than the current cursor position.
	if (cursor->index < cursor->variable.startIndex) {
		EXCEPTION_SET(FIFTYONE_DEGREES_STATUS_CORRUPT_DATA);
		return;
	}
	if (cursor->index > cursor->variable.endIndex) {
		EXCEPTION_SET(FIFTYONE_DEGREES_STATUS_CORRUPT_DATA);
		return;
	}

	// Validate that the index returned is less than the number of entries in
	// the graph collection.
	if (index >= cursor->graph->variablesCount) {
		EXCEPTION_SET(FIFTYONE_DEGREES_STATUS_CORRUPT_DATA);
		return;
	}

	// Next time the set method is called the check to see if the variable 
	// needs to be modified can be applied.
	cursor->variableSet = true;
}

// Extract the value as an integer from the bit packed record provided.
static uint64_t extractValue(
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
	return result;
}

// True if the cursor value is leaf, otherwise false.
static bool isLeaf(Cursor* cursor) {
	bool result = getIsProfileIndex(cursor);
	TRACE_BOOL(cursor, "isLeaf", result);
	return result;
}

// True if the cursor value has the low flag set, otherwise false.
static bool isLowFlag(Cursor* cursor) {
	bool result = getMemberValue(
		cursor->graph->info->value.lowFlag, 
		cursor->current) != 0;
	TRACE_BOOL(cursor, "isLowFlag", result);
	return result;
}

// Moves the cursor to the index in the collection returning the value of the
// record. Uses CgInfo.recordSize to convert the byte array of the record into
// a 64 bit positive integer.
static void cursorMove(Cursor* cursor, uint32_t recordIndex) {
	TRACE_INT(cursor, "cursorMove", recordIndex);

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
	if (EXCEPTION_FAILED) return;

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
	if (EXCEPTION_FAILED) return;
}

// Moves the cursor to the next entry.
static void cursorMoveNext(Cursor* cursor) {
	cursorMove(cursor, cursor->index + 1);
}

// Moves the cursor to the previous entry.
static void cursorMovePrevious(Cursor* cursor) {
	cursorMove(cursor, cursor->index - 1);
}

// Moves the cursor to the entry indicated by the current entry.
static void cursorMoveTo(Cursor* cursor) {
	cursorMove(cursor, (uint32_t)getValue(cursor));
}

// Moves the cursor to the next low entry from the current position.
static void cursorMoveLow(Cursor* cursor) {
	Exception* exception = cursor->ex;
	
	// If the low flag is set then the entry points to the next low entry.
	// Move to it.
	if (isLowFlag(cursor)) {

		// The low entry is a branch so move to it.
		cursorMoveTo(cursor);
		if (EXCEPTION_FAILED) return;
	}

	// If the low flag is not set then the next low entry is the next 
	// consecutive entry. Move to the next entry.
	else {
		cursorMoveNext(cursor);
		if (EXCEPTION_FAILED) return;
	}
}

// Moves the cursor to the next high entry from the current position.
static void cursorMoveHigh(Cursor* cursor) {
	Exception* exception = cursor->ex;

	// If the low flag is set then the next entry is the high entry.
	if (isLowFlag(cursor)) {
		cursorMoveNext(cursor);
		if (EXCEPTION_FAILED) return;
	}

	// Follow the high entry.
	cursorMoveTo(cursor);
	if (EXCEPTION_FAILED) return;
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
	cursor.variableSet = false;
	cursor.compareResult = UNUSED;
	cursor.previousHighIndex = graph->info->graphIndex;
	DataReset(&cursor.item.data);
	return cursor;
}

// Moves the cursor for an low entry.
// Returns true if a leaf has been found and getProfileIndex can be used to
// return a result.
static bool selectLow(Cursor* cursor) {
	Exception* exception = cursor->ex;

	// Check if the current entry is the low entry.
	if (isLowFlag(cursor)) {

		// If a leaf then return, otherwise move to the entry indicated.
		if (isLeaf(cursor)) {
			TRACE_BOOL(cursor, "selectLow", true);
			return true;
		}
		else {
			cursorMoveTo(cursor);
			if (EXCEPTION_FAILED) return true;
		}
	}

	// If the entry is not marked as low then the low entry is the next entry.
	else {
		cursorMoveNext(cursor);
		if (EXCEPTION_FAILED) return true;
	}

	// Return false as no profile index is yet found.
	TRACE_BOOL(cursor, "selectLow", false);
	return false;
}

// Moves the cursor for the high entry.
// Returns true if a leaf has been found and getProfileIndex can be used to
// return a result.
static bool selectHigh(Cursor* cursor) {
	Exception* exception = cursor->ex;

	// An additional check is needed for the data structure as the current
	// entry might relate to the low entry. If this is the case then the next
	// is the one contains the high entry.
	if (isLowFlag(cursor)) {
		cursorMoveNext(cursor);
		if (EXCEPTION_FAILED) return true;
	}

	// Check the current entry to see if it is a high leaf.
	if (isLeaf(cursor)) {
		TRACE_BOOL(cursor, "selectHigh", true);
		return true;
	}

	// Move the cursor to the next entry indicated by the current entry. 
	cursorMoveTo(cursor);
	if (EXCEPTION_FAILED) return true;

	// Completed processing the selected high entry. Return false as no 
	// profile index is yet found.
	TRACE_BOOL(cursor, "selectHigh", false);
	return false;
}

/// <summary>
/// Moves the cursor back to the prior high entry, then follows the low entries
/// until a leaf is found.
/// </summary>
static void selectCompleteHigh(Cursor* cursor) {
	Exception* exception = cursor->ex;
	TRACE_LABEL(cursor, "selectCompleteHigh");
	while (selectHigh(cursor) == false) {
		if (EXCEPTION_FAILED) return;
	}
}

/// <summary>
/// Follows the low entry before taking all the high entries until a leaf is
/// found.
/// </summary>
static void selectCompleteLowHigh(Cursor* cursor) {
	Exception* exception = cursor->ex;
	TRACE_LABEL(cursor, "selectCompleteLowHigh");
	if (selectLow(cursor) == false) {
		while (selectHigh(cursor) == false) {
			if (EXCEPTION_FAILED) return;
		}
	}
}

// Moves the cursor back to the previous high entry, and then selects low.
// Returns true if a leaf is found, otherwise false.
static bool cursorMoveBack(Cursor* cursor) {
	Exception* exception = cursor->ex;
	TRACE_LABEL(cursor, "cursorMoveBack");
	cursorMove(cursor, cursor->previousHighIndex);
	if (EXCEPTION_FAILED) return true;
	return selectLow(cursor);
}

/// <summary>
/// Moves the cursor back to the prior low entry, then follows the high entries
/// until a leaf is found.
/// </summary>
static void selectCompleteLow(Cursor* cursor) {
	Exception* exception = cursor->ex;
	TRACE_LABEL(cursor, "selectCompleteLow");
	if (cursorMoveBack(cursor) == false) {
		if (EXCEPTION_FAILED) return;
		while (selectHigh(cursor) == false) {
			if (EXCEPTION_FAILED) return;
		}
	}
}

// Compares the current variable to the relevant bits in the IP address. The
// comparison varies depending on whether the limit is lower or higher than the
// equal variable.
static void compareIpToVariable(Cursor* cursor) {
	Exception* exception = cursor->ex;

	// Set the cursor->ipValue to the required bits from the IP address for
	// numeric comparison.
	setIpValue(cursor); 

	// Set the comparison result.
	if (cursor->ipValue < cursor->variable.low) {
		cursor->compareResult = LESS_THAN_LOW;
	}
	else if (cursor->ipValue == cursor->variable.low) {
		cursor->compareResult = EQUAL_LOW;
	}
	else if (cursor->ipValue > cursor->variable.low &&
		cursor->ipValue < cursor->variable.high) {
		cursor->compareResult = INBETWEEN;
	}
	else if (cursor->ipValue == cursor->variable.high) {
		cursor->compareResult = EQUAL_HIGH;
		cursor->previousHighIndex = cursor->index;
	}
	else {
		cursor->compareResult = GREATER_THAN_HIGH;
	}

	// If tracing enabled output the results.
	TRACE_COMPARE(cursor);
}

// Evaluates the cursor until a leaf is found and then returns the profile
// index.
static uint32_t evaluate(Cursor* cursor) {
	Exception* exception = cursor->ex;
	bool found = false;
	traceNewLine(cursor);

	// Move the cursor to the entry record for the graph.
	cursorMove(cursor, cursor->graph->info->graphIndex);

	do
	{
		// Compare the current cursor bits against the variable value.
		compareIpToVariable(cursor);

		// Advance the bits before the variable is then changed.
		cursor->bitIndex += cursor->variable.length;

		switch (cursor->compareResult) {
		case LESS_THAN_LOW:
			selectCompleteLow(cursor);
			if (EXCEPTION_FAILED) return 0;
			found = true;
			break;
		case EQUAL_LOW:
			found = selectLow(cursor);
			if (EXCEPTION_FAILED) return 0;
			break;
		case INBETWEEN:
			selectCompleteLowHigh(cursor);
			if (EXCEPTION_FAILED) return 0;
			found = true;
			break;
		case EQUAL_HIGH:
			found = selectHigh(cursor);
			if (EXCEPTION_FAILED) return 0;
			break;
		case GREATER_THAN_HIGH:
			selectCompleteHigh(cursor);
			if (EXCEPTION_FAILED) return 0;
			found = true;
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
			TRACE_RESULT(&cursor, profileIndex);
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
		graphs->items[i].variablesCount = CollectionGetCount(
			graphs->items[i].variables);
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