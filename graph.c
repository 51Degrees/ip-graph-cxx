/* *********************************************************************
 * This Original Work is copyright of 51 Degrees Mobile Experts Limited.
 * Copyright 2025 51 Degrees Mobile Experts Limited, Davidson House,
 * Forbury Square, Reading, Berkshire, United Kingdom RG1 3EU.
 *
 * This Original Work is the subject of the following patent application, 
 * owned by 51 Degrees Mobile Experts Limited of
 * Regus Forbury Square, Davidson House, Reading RG1 3EU, United Kingdom:
 * United Kingdom Patent Application No. 2506025.2.
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
 * ********************************************************************* */

#include "graph.h"

#include "../common-cxx/collectionKeyTypes.h"
#include "../common-cxx/fiftyone.h"

MAP_TYPE(IpiCg)
MAP_TYPE(IpiCgArray)
MAP_TYPE(IpiCgMember)
MAP_TYPE(IpiCgInfo)
MAP_TYPE(Collection)

/**
 * RESULTS FROM COMPARE OPERATIONS - THE IP ADDRESS SEGMENT IS;
 */
typedef enum {
	NO_COMPARE,
	LESS_THAN_LOW,
	EQUAL_LOW,
	INBETWEEN,
	EQUAL_HIGH,
	GREATER_THAN_HIGH
} CompareResult;

// Number of bytes that can form an IP value or span limit.
#define VAR_SIZE 16

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

// Structure for the span.
#pragma pack(push, 1)
typedef struct span_t {
	byte lengthLow; // Bit length of the low span limit
	byte lengthHigh; // Bit length of the high span limit
	union {
		uint32_t offset; // Offset to the span bytes
		byte limits[4]; // Array of 4 bytes with the low and high bits
	} trail;
} Span;
#pragma pack(pop)

// Structure for the cluster.
#pragma pack(push, 1)
typedef struct cluster_t {
	uint32_t startIndex; // The inclusive start index in the nodes collection
	uint32_t endIndex; // The inclusive end index in the nodes collection
	uint32_t spanIndexes[256]; // The span indexes for the cluster
} Cluster;
#pragma pack(pop)

// Cursor used to traverse the graph for each of the bits in the IP address.
typedef struct cursor_t {
	const IpiCg* const graph; // Graph the cursor is working with
	IpAddress const ip; // The IP address source
	CollectionKeyType nodeBytesKeyType; // keyType for extracting node bytes
	byte ipValue[VAR_SIZE]; // The value that should be compared to the span
	byte bitIndex; // Current bit index from high to low in the IP address 
				   // value array
	uint64_t nodeBits; // The value of the current item in the graph
	uint32_t index; // The current index in the graph values collection
	uint32_t previousHighIndex; // The index of the last high index
	struct ClusterWrapper {
		uint32_t index; // The current cluster index
		const Cluster* ptr; // typed pointer to the memory (for convenience)
		Item item; // item that owns the memory
	} cluster; // The current cluster that relates to the node index
	uint32_t spanIndex; // The current span index
	Span span; // The current span that relates to the node index
	byte spanLow[VAR_SIZE]; // Low limit for the span
	byte spanHigh[VAR_SIZE]; // High limit for the span
	byte spanSet; // True after the first time the span is set
	CompareResult compareResult; // Result of comparing the current bits to the
								 // span value
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
#define TRACE_BOOL(c,m,v)
#define TRACE_INT(c,m,v)
#define TRACE_COMPARE(c)
#define TRACE_LABEL(c,m)
#define TRACE_RESULT(c,r)
#endif

// Get the bit as a bool for the byte array and bit index from the left. High
// order bit is index 0.
#define GET_BIT(b,i) ((((b)[(i) / 8] >> (7 - ((i) % 8))) & 1))

// Sets the bit in the destination byte array where the bit index is from 
// left. High order bit is index 0.
#define SET_BIT(b,i) (b[i / 8] |= 1 << (7 - (i % 8)))

// Outputs to the string builder the bits from left to right from the bytes
// provided.
static void bytesToBinary(
	const Cursor * const cursor,
	const byte * const bytes,
	const int length) {
	int count = 0;
	for (int i = 0; i < length; i++)
	{
		StringBuilderAddChar(cursor->sb, GET_BIT(bytes, i) ? '1' : '0');
		count++;
		if (count % 4 == 0 && count < length) {
			StringBuilderAddChar(cursor->sb, ' ');
		}
	}
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

// The IpType for the component graph.
static IpType getIpTypeFromGraph(const IpiCgInfo* const info) {
	return getIpTypeFromVersion(info->version);
}

// Manipulates the source using the mask and shift parameters of the member.
static uint32_t getMemberValue(IpiCgMember member, uint64_t source) {
	return (uint32_t)((source & member.mask) >> member.shift);
}

// Returns the value from the current node value.
static uint32_t getValue(const Cursor* const cursor) {
	uint32_t result = getMemberValue(
		cursor->graph->info.nodes.value,
		cursor->nodeBits);
	return result;
}

// Returns the cluster span index from the current node value.
static uint32_t getSpanIndexCluster(const Cursor* const cursor) {
	uint32_t result = getMemberValue(
		cursor->graph->info.nodes.spanIndex,
		cursor->nodeBits);
	return result;
}

// Returns the real span index from the cluster span index.
static uint32_t getSpanIndex(
	const Cursor* const cursor,
	const uint32_t clusterSpanIndex) {
	return cursor->cluster.ptr->spanIndexes[clusterSpanIndex];
}

// The larger of the two span limits.
static int getMaxSpanLimitLength(const Cursor* const cursor) {
	return cursor->span.lengthLow > cursor->span.lengthHigh ?
		cursor->span.lengthLow :
		cursor->span.lengthHigh;
}

// The total length of the bits in the span limits.
static int getTotalSpanLimitLength(const Cursor* const cursor) {
	return cursor->span.lengthLow + cursor->span.lengthHigh;
}

static void traceNewLine(const Cursor* const cursor) {
	StringBuilderAddChar(cursor->sb, '\r');
	StringBuilderAddChar(cursor->sb, '\n');
}

static void traceLabel(const Cursor* const cursor, const char* label) {
	StringBuilderAddChar(cursor->sb, '\t');
	StringBuilderAddChars(cursor->sb, label, strlen(label));
	traceNewLine(cursor);
}

#define TRACE_TRUE "true"
#define TRACE_FALSE "false"
static void traceBool(
	const Cursor* const cursor,
	const char* const method,
	const bool value) {
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

static void traceInt(
	const Cursor* const cursor,
	const char* const method,
	const int64_t value) {
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
#define NC "NO_COMPARE"
#define IP "IP:" // IP value
#define LV "LV:" // Low Value
#define HV "HV:" // High Value
#define CLI "CLI:" // Cluster Index
#define SI "SI:" // Span Index
#define CI "CI:" // Cursor Index
static void traceCompare(const Cursor* const cursor) {
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
	case NO_COMPARE:
		StringBuilderAddChars(cursor->sb, NC, sizeof(NC) - 1);
		break;
	}
	StringBuilderAddChar(cursor->sb, ' ');
	StringBuilderAddChars(cursor->sb, IP, sizeof(IP) - 1);
	bytesToBinary(cursor, cursor->ipValue, getMaxSpanLimitLength(cursor));
	StringBuilderAddChar(cursor->sb, ' ');
	StringBuilderAddChars(cursor->sb, LV, sizeof(LV) - 1);
	bytesToBinary(cursor, cursor->spanLow, cursor->span.lengthLow);
	StringBuilderAddChar(cursor->sb, ' ');
	StringBuilderAddChars(cursor->sb, HV, sizeof(HV) - 1);
	bytesToBinary(cursor, cursor->spanHigh, cursor->span.lengthHigh);
	StringBuilderAddChar(cursor->sb, ' ');
	StringBuilderAddChars(cursor->sb, CLI, sizeof(CLI) - 1);
	StringBuilderAddInteger(cursor->sb, cursor->cluster.index);
	StringBuilderAddChar(cursor->sb, ' ');
	StringBuilderAddChars(cursor->sb, SI, sizeof(SI) - 1);
	StringBuilderAddInteger(cursor->sb, cursor->spanIndex);
	StringBuilderAddChar(cursor->sb, ' ');
	StringBuilderAddChars(cursor->sb, CI, sizeof(CI) - 1);
	StringBuilderAddInteger(cursor->sb, cursor->index);
	traceNewLine(cursor);
}

static void traceMove(Cursor* cursor, const char* method) {
	StringBuilderAddChar(cursor->sb, '\t');
	StringBuilderAddChars(cursor->sb, method, strlen(method));
	StringBuilderAddChar(cursor->sb, ' ');
	StringBuilderAddInteger(cursor->sb, cursor->index);
	StringBuilderAddChar(cursor->sb, ' ');
	StringBuilderAddInteger(cursor->sb, cursor->spanIndex);
	StringBuilderAddChar(cursor->sb, ' ');
	bytesToBinary(cursor, (byte*)&cursor->nodeBits, 64);
	traceNewLine(cursor);
}

#define RESULT "result"
#define RAWRESULT "raw result"
#define ISGROUP "is group"
static void traceResult(const Cursor* const cursor, const fiftyoneDegreesIpiCgResult result) {
	traceNewLine(cursor);
	StringBuilderAddChars(cursor->sb, RESULT, sizeof(RESULT) - 1);
	StringBuilderAddChar(cursor->sb, '=');
	StringBuilderAddInteger(cursor->sb, (int)result.offset);
	traceNewLine(cursor);
	StringBuilderAddChars(cursor->sb, RAWRESULT, sizeof(RAWRESULT) - 1);
	StringBuilderAddChar(cursor->sb, '=');
	StringBuilderAddInteger(cursor->sb, (int)result.rawOffset);
	traceNewLine(cursor);
	StringBuilderAddChars(cursor->sb, ISGROUP, sizeof(ISGROUP) - 1);
	StringBuilderAddChar(cursor->sb, '=');
	StringBuilderAddInteger(cursor->sb, (int)result.isGroupOffset);
	traceNewLine(cursor);
}

// The index of the profile associated with the value if this is a leaf value.
// getIsProfileIndex must be called before getting the profile index.
static uint32_t getProfileIndex(const Cursor* const cursor) {
	uint32_t result = (uint32_t)(
		getValue(cursor) - cursor->graph->info.nodes.collection.count);
	return result;
}

// True if the cursor is currently positioned on a leaf and therefore profile 
// index.
static bool getIsProfileIndex(const Cursor* const cursor) {
	bool result = getValue(cursor) >=
		cursor->graph->info.nodes.collection.count;
	TRACE_BOOL(cursor, "getIsProfileIndex", result);
	return result;
}

// True if the cursor value is leaf, otherwise false.
static bool isLeaf(const Cursor* const cursor) {
	bool result = getIsProfileIndex(cursor);
	TRACE_BOOL(cursor, "isLeaf", result);
	return result;
}

// True if the cursor value has the low flag set, otherwise false.
static bool isLowFlag(const Cursor* const cursor) {
	bool result = getMemberValue(
		cursor->graph->info.nodes.lowFlag,
		cursor->nodeBits) != 0;
	TRACE_BOOL(cursor, "isLowFlag", result);
	return result;
}

// Resets the bytes to zero.
static void bytesReset(byte* bytes) {
	memset(bytes, 0, VAR_SIZE);
}

// If the bits of first and second that are needed to cover the bits are equal
// returns 0, otherwise -1 or 1 depending on whether they are higher or lower.
static int bitsCompare(
	const byte* const first,
	const byte* const second,
	const int bits) {
	for (int i = 0; i < bits; i++) {
		int firstBit = GET_BIT(first, i);
		int secondBit = GET_BIT(second, i);
		if (firstBit < secondBit) {
			return -1;
		}
		if (firstBit > secondBit) {
			return 1;
		}
	}
	return 0;
}

// Copies bits from the source to the destination starting at the start bit in
// the source provided and including the subsequent bits.
static void copyBits(byte* dest, const byte* src, int startBit, int bits) {
	for (int i = 0, s = startBit; i < bits; i++, s++) {

		// If 1 then set the bit in the destination.
		if (GET_BIT(src, s)) {
			SET_BIT(dest, i);
		}
	}
}

// Sets the cursor->ipValue to the bits needed to perform an integer comparison
// operation with the cursor->span.
static void setIpValue(Cursor* cursor) {
	
	// Reset the IP value ready to include the new bits.
	bytesReset(cursor->ipValue);

	// Copy the bits from the IP address to the compare field.
	copyBits(
		cursor->ipValue, 
		cursor->ip.value, 
		cursor->bitIndex,
		getMaxSpanLimitLength(cursor));
}

// True if all the bytes of the address have been consumed.
static bool isExhausted(const Cursor* const cursor) {
	byte byteIndex = cursor->bitIndex / 8;
	return byteIndex >= sizeof(cursor->ip.value);
}

// Comparer used to determine if the selected cluster is higher or lower than
// the target.
static int setClusterComparer(
	Cursor* const cursor,
	Item* const item) {
	// Swap the ownership, so that Cursor now owns this item
	{
		const Item t = cursor->cluster.item;
		cursor->cluster.item = *item;
		cursor->cluster.ptr = (const Cluster*)item->data.ptr;
		*item = t;
	}

	// If this cluster is within the require range then its the correct one
	// to return.
	const uint32_t searchIndex = cursor->index;
	const uint32_t startIndex = cursor->cluster.ptr->startIndex;
	if (searchIndex >= startIndex &&
		searchIndex <= cursor->cluster.ptr->endIndex) {
		return 0;
	}

	return (startIndex > searchIndex) ? 1 : (startIndex < searchIndex) ? -1 : 0;
}

static uint32_t setClusterSearch(
	const fiftyoneDegreesCollection* const collection,
	const uint32_t lowerIndex,
	const uint32_t upperIndex,
	Cursor* const cursor,
	fiftyoneDegreesException* exception) {
	uint32_t upper = upperIndex,
		lower = lowerIndex,
		middle = 0;
	const CollectionKeyType keyType = {
		FIFTYONE_DEGREES_COLLECTION_ENTRY_TYPE_GRAPH_DATA_CLUSTER,
		collection->elementSize,
		NULL,
	};
	while (lower <= upper) {
		fiftyoneDegreesCollectionItem item;
		DataReset(&item.data);

		// Get the middle index for the next item to be compared.
		middle = lower + (upper - lower) / 2;

		// Get the item from the collection checking for NULL or an error.
		const CollectionKey key = {
			middle,
			&keyType,
		};
		if (collection->get(collection, &key, &item, exception) == NULL ||
			EXCEPTION_OKAY == false) {
			return 0;
		}

		// Perform the binary search using the comparer provided with the item
		// just returned.
        
        // setClusterComparer does a clever hack by moving ownership of the
        // item's memory into the cursor->cluster, and moving the ownership of
        // a previously fetched item from cursor->cluster back to item
        // essentially it's a swap of pointers, ownership means:
        // who is responsible for freeing that memory, so essentially after a
        // call to setClusterComparer the item will be owned by this code,
        // but it will be the one retrieved on a previous iteration of the loop
		const int comparisonResult = setClusterComparer(cursor, &item);
        
        // Item is now the one from previous iteration, so needs to be freed
		if (item.collection) {
			COLLECTION_RELEASE(collection, &item);
		}
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
	}

	// The item could not be found so return the index of the span that covers 
	// the range required.
	return middle;
}

static void setCluster(Cursor* cursor) {
	Exception* exception = cursor->ex;

	// If the cluster is set and already at the correct index position then
	// don't change.
	if (cursor->cluster.ptr &&
		cursor->index >= cursor->cluster.ptr->startIndex &&
		cursor->index <= cursor->cluster.ptr->endIndex) {
		return;
	}

	// Use binary search to find the index for the cluster. The comparer
	// records the last cluster checked the cursor will have the correct 
	// cluster after the search operation.
	const uint32_t index = setClusterSearch(
		cursor->graph->clusters,
		0,
		cursor->graph->clustersCount - 1,
		cursor,
		cursor->ex);

	// Validate that the cluster set has a start index equal to or greater than
	// the current cursor position.
	if (cursor->index < cursor->cluster.ptr->startIndex) {
		EXCEPTION_SET(FIFTYONE_DEGREES_STATUS_CORRUPT_DATA);
		return;
	}
	if (cursor->index > cursor->cluster.ptr->endIndex) {
		EXCEPTION_SET(FIFTYONE_DEGREES_STATUS_CORRUPT_DATA);
		return;
	}

	// Validate that the index returned is less than the number of entries in
	// the graph collection.
	if (index >= cursor->graph->clustersCount) {
		EXCEPTION_SET(FIFTYONE_DEGREES_STATUS_CORRUPT_DATA);
		return;
	}

	// Next time the set method is called the check to see if the cluster needs
	// to be modified can be applied.
	cursor->cluster.index = index;
}

// Set the span low and high limits from the offset.
static void setSpanBytes(Cursor* cursor) {
	Exception* exception = cursor->ex;
	
	// Use the current span offset to get the bytes.
	Item cursorItem;
	DataReset(&cursorItem.data);
	const uint32_t totalBits = cursor->span.lengthLow + cursor->span.lengthHigh;
	const uint32_t totalBytes = (totalBits / 8) + ((totalBits % 8) ? 1 : 0);
	const CollectionKeyType keyType = {
		FIFTYONE_DEGREES_COLLECTION_ENTRY_TYPE_GRAPH_DATA_SPAN_BYTES,
		totalBytes,
		NULL,
	};
	const CollectionKey spanBytesKey = {
		cursor->span.trail.offset,
		&keyType,
	};
	byte* bytes = cursor->graph->spanBytes->get(
		cursor->graph->spanBytes,
		&spanBytesKey,
		&cursorItem,
		cursor->ex);
	if (EXCEPTION_FAILED) return;

	// Copy the bits to the low and high bytes ready for comparison.
	copyBits(
		cursor->spanLow, 
		bytes, 
		0,
		cursor->span.lengthLow);
	copyBits(
		cursor->spanHigh,
		bytes,
		cursor->span.lengthLow, 
		cursor->span.lengthHigh);

	COLLECTION_RELEASE(cursor->graph->spanBytes, &cursorItem);

	if (bitsCompare(
		cursor->spanLow, 
		cursor->spanHigh, 
		getMaxSpanLimitLength(cursor)) >= 0) {
		EXCEPTION_SET(FIFTYONE_DEGREES_STATUS_CORRUPT_DATA);
		return;
	}
}

// Set the span low and high limits from the limits bytes.
void setSpanLimits(Cursor* cursor) {
	copyBits(
		cursor->spanLow,
		cursor->span.trail.limits,
		0,
		cursor->span.lengthLow);
	copyBits(
		cursor->spanHigh,
		cursor->span.trail.limits,
		cursor->span.lengthLow,
		cursor->span.lengthHigh);
}

static const CollectionKeyType CollectionKeyType_Span = {
	FIFTYONE_DEGREES_COLLECTION_ENTRY_TYPE_GRAPH_DATA_SPAN,
	sizeof(Span),
	NULL,
};

// Sets the cursor span to the correct settings for the current node value 
// index. Uses the binary search feature of the collection.
static void setSpan(Cursor* cursor) {
	Exception* exception = cursor->ex;

	// First ensure that the correct cluster is set.
	setCluster(cursor);
	if (EXCEPTION_FAILED) return;

	// Get the cluster span index.
	uint32_t spanIndexCluster = getSpanIndexCluster(cursor);

	// Get the actual span index.
	uint32_t spanIndex = getSpanIndex(cursor, spanIndexCluster);

	// Check if the span needs to be updated.
	if (cursor->spanSet && cursor->spanIndex == spanIndex) {
		return;
	}

	// Validate that the index returned is less than the number of entries in
	// the graph collection.
	if (spanIndex >= cursor->graph->spansCount) {
		EXCEPTION_SET(FIFTYONE_DEGREES_STATUS_CORRUPT_DATA);
		return;
	}

	// Set the span for the current span index.
	Item cursorItem;
	DataReset(&cursorItem.data);
	const CollectionKey spanKey = {
		spanIndex,
		&CollectionKeyType_Span,
	};
	Span * const span = (Span*)cursor->graph->spans->get(
		cursor->graph->spans,
		&spanKey,
		&cursorItem,
		exception);
	if (!span || EXCEPTION_FAILED) return;
	cursor->span = *span;
	COLLECTION_RELEASE(cursor->graph->spans, &cursorItem);

	// Ensure set to 0s before the bits are copied.
	bytesReset(cursor->spanLow);
	bytesReset(cursor->spanHigh);

	// If the span is more than 32 bits then the span bytes are contained in
	// the span bytes collection.
	if (getTotalSpanLimitLength(cursor) > 32) {
		setSpanBytes(cursor);
		if (EXCEPTION_FAILED) return;
	}
	else {
		setSpanLimits(cursor);
	}

	// Next time the set method is called the check to see if the span needs to
	// be modified can be applied.
	cursor->spanSet = true;
	cursor->spanIndex = spanIndex;
}

/// Extract `bitCount` bits from `byteValue` starting at `startBit`
/// @param byteValue raw (full) byte
/// @param startBit first bit to extract (0 -- MSB, 7 -- LSB)
/// @param bitCount how many (less significant) bits to extract
/// @return extracted value
static uint8_t extractSubValue(
	uint8_t byteValue,
	uint8_t startBit,
	uint8_t bitCount) {
	const uint8_t mask = (1 << bitCount) - 1;
	const uint8_t rightOffset = 8 - startBit - bitCount;
	return (byteValue >> rightOffset) & mask;
}

/// Extract the value as uint64_t from the bit packed record provided.
/// @param source pointer to first byte
/// @param recordSize how many total bits to extract
/// @param bitIndex first bit to extract (0 -- MSB, 7 -- LSB) from first byte
/// @return extracted value
static uint64_t extractValue(
	const uint8_t* const source,
	const uint16_t recordSize,
	const uint8_t bitIndex) {

	uint64_t result;
	{
		const uint8_t bitsAvailable = 8 - bitIndex;
		result = extractSubValue(
			*source,
			bitIndex,
			(bitsAvailable < recordSize) ? bitsAvailable : (uint8_t)recordSize);
	}
	int remainingBits = recordSize + bitIndex - 8;

	const uint8_t *nextByte = source + 1;
	for (; remainingBits >= 8; remainingBits -= 8, ++nextByte) {
		result <<= 8;
		result |= *nextByte;
	}

	if (remainingBits > 0) {
		result <<= remainingBits;
		result |= extractSubValue(*nextByte, 0, (uint8_t)remainingBits);
	}

	return result;
}

// Moves the cursor to the index in the collection returning the value of the
// record. Uses CgInfo.recordSize to convert the byte array of the record into
// a 64 bit positive integer.
static void cursorMove(Cursor* const cursor, const uint32_t index) {
	Exception* const exception = cursor->ex;

	// Work out the byte index for the record index and the starting bit index
	// within that byte.
	uint64_t startBitIndex = index;
	startBitIndex *= cursor->graph->info.nodes.recordSize;
	const uint64_t byteIndex = startBitIndex / 8;
	const byte bitIndex = startBitIndex % 8;

	// Get a pointer to that byte from the collection.
	Item cursorItem;
	DataReset(&cursorItem.data);
	const uint32_t totalBits = cursor->graph->info.nodes.recordSize + bitIndex;
	const uint32_t totalBytes = (totalBits / 8) + ((totalBits % 8) ? 1 : 0);
	CollectionKeyType * const nodeBytesKeyType = &cursor->nodeBytesKeyType;
	nodeBytesKeyType->initialBytesCount = totalBytes;
	const CollectionKey nodeBytesKey = {
		(uint32_t)byteIndex,
		nodeBytesKeyType,
	};
	const byte* const ptr = (byte*)cursor->graph->nodes->get(
		cursor->graph->nodes,
		&nodeBytesKey,
		&cursorItem,
		exception);
	if (EXCEPTION_FAILED) return;

	// Move the bits in the bytes pointed to create the unsigned 64 bit integer
	// that contains the node value bits.
	cursor->nodeBits = extractValue(
		ptr,
		cursor->graph->info.nodes.recordSize,
		bitIndex);

	// Release the data item.
	COLLECTION_RELEASE(cursorItem.collection, &cursorItem);

	// Set the record index.
	cursor->index = index;

	// Set the correct span to use for any compare operations.
	setSpan(cursor);

	if (EXCEPTION_FAILED) return;
}

// Moves the cursor to the entry indicated by the current entry.
static void cursorMoveTo(Cursor* cursor) {
	cursorMove(cursor, (uint32_t)getValue(cursor));
}

// Moves the cursor to the next entry.
static void cursorMoveNext(Cursor* cursor) {
	cursorMove(cursor, cursor->index + 1);
}

// Creates a cursor ready for evaluation with the graph and IP address.
static Cursor cursorCreate(
	const IpiCg* const graph,
	IpAddress ip,
	StringBuilder* sb,
	Exception* exception) {
	Cursor cursor = {
		graph,
		ip,
		{ // nodeBytesKeyType
			FIFTYONE_DEGREES_COLLECTION_ENTRY_TYPE_GRAPH_DATA_NODE_BYTES,
			0, // TBD
			NULL,
		},
	};
	bytesReset(cursor.ipValue);
	cursor.bitIndex = 0;
	cursor.nodeBits = 0;
	cursor.index = 0;
	cursor.previousHighIndex = graph->info.graphIndex;
	cursor.cluster.index = 0;
	cursor.cluster.ptr = NULL;
	DataReset(&cursor.cluster.item.data);
	cursor.cluster.item.handle = NULL;
	cursor.cluster.item.collection = NULL;
	cursor.spanIndex = 0;
	cursor.span.lengthLow = 0;
	cursor.span.lengthHigh = 0;
	cursor.span.trail.offset = 0;
	cursor.spanSet = false;
	cursor.compareResult = NO_COMPARE;
	cursor.sb = sb;
	cursor.ex = exception;
	return cursor;
}

static void cursorReleaseData(Cursor* const cursor) {
	if (cursor->cluster.ptr) {
		COLLECTION_RELEASE(
			cursor->cluster.item.collection,
			&cursor->cluster.item);
	}
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

// Moves the cursor back to the previous high entry, and then selects low.
// Returns true if a leaf is found, otherwise false.
static bool cursorMoveBackLow(Cursor* cursor) {
	Exception* exception = cursor->ex;
	TRACE_LABEL(cursor, "cursorMoveBack");
	cursorMove(cursor, cursor->previousHighIndex);
	if (EXCEPTION_FAILED) return true;
	return selectLow(cursor);
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

// Moves the cursor back to the prior high entry, then follows the low entries
// until a leaf is found.
static void selectCompleteHigh(Cursor* cursor) {
	Exception* exception = cursor->ex;
	TRACE_LABEL(cursor, "selectCompleteHigh");
	while (selectHigh(cursor) == false) {
		if (EXCEPTION_FAILED) return;
	}
}

// Follows the low entry before taking all the high entries until a leaf is
// found.
static void selectCompleteLowHigh(Cursor* cursor) {
	Exception* exception = cursor->ex;
	TRACE_LABEL(cursor, "selectCompleteLowHigh");
	if (selectLow(cursor) == false) {
		while (selectHigh(cursor) == false) {
			if (EXCEPTION_FAILED) return;
		}
	}
}

// Moves the cursor back to the prior low entry, then follows the high entries
// until a leaf is found.
static void selectCompleteLow(Cursor* cursor) {
	Exception* exception = cursor->ex;
	TRACE_LABEL(cursor, "selectCompleteLow");
	if (cursorMoveBackLow(cursor) == false) {
		if (EXCEPTION_FAILED) return;
		while (selectHigh(cursor) == false) {
			if (EXCEPTION_FAILED) return;
		}
	}
}

// Compares the current span to the relevant bits in the IP address. The
// comparison varies depending on whether the limit is lower or higher than the
// equal span.
static void compareIpToSpan(Cursor* cursor) {
	// Set the cursor->ipValue to the required bits from the IP address for
	// numeric comparison.
	setIpValue(cursor); 

	// Set the comparison result.
	int lowCompare = bitsCompare(
		cursor->ipValue,
		cursor->spanLow,
		cursor->span.lengthLow);
	int highCompare = bitsCompare(
		cursor->ipValue,
		cursor->spanHigh,
		cursor->span.lengthHigh);
	if (lowCompare < 0) {
		cursor->compareResult = LESS_THAN_LOW;
	}
	else if (lowCompare == 0) {
		cursor->compareResult = EQUAL_LOW;
	}
	else if (lowCompare > 0 && highCompare < 0)
	{
		cursor->compareResult = INBETWEEN;
	}
	else if (highCompare == 0) {
		cursor->compareResult = EQUAL_HIGH;
		cursor->previousHighIndex = cursor->index;
	}
	else if (highCompare > 0) {
		cursor->compareResult = GREATER_THAN_HIGH;
	}
	else {
		// Should never happen.
		cursor->compareResult = NO_COMPARE;
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

	// Move the cursor to the entry for the graph.
	cursorMove(cursor, cursor->graph->info.graphIndex);
	if (EXCEPTION_FAILED) return 0;

	do
	{
		// Compare the current cursor IP bits against the span limits.
		compareIpToSpan(cursor);

		switch (cursor->compareResult) {
		case LESS_THAN_LOW:
			selectCompleteLow(cursor);
			if (EXCEPTION_FAILED) return 0;
			found = true;
			break;
		case EQUAL_LOW:
			// Advance the bits before the cursor is changed.
			cursor->bitIndex += cursor->span.lengthLow;
			found = selectLow(cursor);
			if (EXCEPTION_FAILED) return 0;
			break;
		case INBETWEEN:
			selectCompleteLowHigh(cursor);
			if (EXCEPTION_FAILED) return 0;
			found = true;
			break;
		case EQUAL_HIGH:
			// Advance the bits before the cursor is changed.
			cursor->bitIndex += cursor->span.lengthHigh;
			found = selectHigh(cursor);
			if (EXCEPTION_FAILED) return 0;
			break;
		case GREATER_THAN_HIGH:
			selectCompleteHigh(cursor);
			if (EXCEPTION_FAILED) return 0;
			found = true;
			break;
		default:
			EXCEPTION_SET(FIFTYONE_DEGREES_STATUS_CORRUPT_DATA);
			return UINT32_MAX;
		}

 	} while (found == false && isExhausted(cursor) == false);
	return getProfileIndex(cursor);
}

// Applies profile mappings from graph info to evaluation result.
// profileIndex - Value returned by the graph.
// graph - Graph that returned the value.
// Returns the mapped profile/group offset and type flag.
static fiftyoneDegreesIpiCgResult toResult(
	const uint32_t profileIndex,
	const IpiCg * const graph,
	Exception *exception) {
	fiftyoneDegreesIpiCgResult result = {
		profileIndex,
		0,
		false,
	};
	if (profileIndex < graph->info.profileCount) {
		result.offset = profileIndex + graph->info.firstProfileIndex;
	}
	else {
		const uint32_t groupIndex = profileIndex - graph->info.profileCount;
		if (groupIndex < graph->info.profileGroupCount) {
			result.offset = groupIndex + graph->info.firstProfileGroupIndex;
			result.isGroupOffset = true;
		}
		else {
			EXCEPTION_SET(CORRUPT_DATA);
		}
	}
	return result;
}

static fiftyoneDegreesIpiCgResult ipiGraphEvaluate(
	const fiftyoneDegreesIpiCgArray * const graphs,
	byte componentId,
	fiftyoneDegreesIpAddress address,
	StringBuilder* sb,
	fiftyoneDegreesException* exception) {
	fiftyoneDegreesIpiCgResult result = FIFTYONE_DEGREES_IPI_CG_RESULT_DEFAULT;
	for (uint32_t i = 0; i < graphs->count; i++) {
		const IpiCg* const graph = &graphs->items[i];
		if (address.type == graph->info.version &&
			componentId == graph->info.componentId) {
			Cursor cursor = cursorCreate(graph, address, sb, exception);
			const uint32_t profileIndex = evaluate(&cursor);
			if (EXCEPTION_OKAY) {
				result = toResult(profileIndex, graph, exception);
				TRACE_RESULT(&cursor, result);
			}
			cursorReleaseData(&cursor);
			break;
		}
	}
	return result;
}

// Graph headers might be duplicated across different graphs. As such the 
// reader passed may not be at the first byte of the graph being created. The
// current reader position is therefore modified to that of the header and then
// reset after the operation.
static Collection* ipiGraphCreateFromFile(
	CollectionHeader header,
	void* state) {
	FileCollection * const s = (FileCollection*)state;

	const FileOffset current = FileTell(s->file);
	if (current < 0) {
		return NULL;
	}
	const FileOffset target = (FileOffset)header.startPosition;
	const bool shouldRestore = current != target;
	if (shouldRestore) {
		if (FileSeek(s->file, target, SEEK_SET)) {
			return NULL;
		}
	}
	Collection* collection = CollectionCreateFromFile(
		s->file,
		s->reader,
		&s->config,
		header,
		CollectionReadFileFixed);
	if (shouldRestore) {
		FileSeek(s->file, current, SEEK_SET);
	}
	return collection;
}

// Graph headers might be duplicated across different graphs. As such the 
// reader passed may not be at the first byte of the graph being created. The
// current reader position is therefore modified to that of the header and then
// reset after the operation.
static Collection* ipiGraphCreateFromMemory(
	CollectionHeader header, 
	void* state) {
	MemoryReader* const reader = (MemoryReader*)state;
	byte* const current = reader->current;
	byte* const target = reader->startByte + header.startPosition;
	const bool shouldRestore = current != target;
	if (shouldRestore) {
		reader->current = target;
	}
	Collection* collection = CollectionCreateFromMemory(
		(MemoryReader*)state,
		header);
	if (shouldRestore) {
		reader->current = current;
	}
	return collection;
}

static const CollectionKeyType CollectionKeyType_GraphInfo = {
	FIFTYONE_DEGREES_COLLECTION_ENTRY_TYPE_GRAPH_INFO,
	sizeof(IpiCgInfo),
	NULL,
};

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
		graphs->items[i].nodes = NULL;
		graphs->items[i].spans = NULL;

		Item itemInfo;
		DataReset(&itemInfo.data);

		// Get the information from the collection provided.
		const CollectionKey infoKey = {
			i,
			&CollectionKeyType_GraphInfo,
		};
		const IpiCgInfo* const info = (IpiCgInfo*)collection->get(
			collection, 
			&infoKey,
			&itemInfo,
			exception);
		if (EXCEPTION_FAILED) {
			fiftyoneDegreesIpiGraphFree(graphs);
			return NULL;
		}
		graphs->items[i].info = *info;
		COLLECTION_RELEASE(collection, &itemInfo);
		graphs->count++;

		// Create the collection for the node values. Must overwrite the count
		// to zero as it is consumed as a variable width collection.
		CollectionHeader headerNodes = graphs->items[i].info.nodes.collection;
		headerNodes.count = headerNodes.length;
		graphs->items[i].nodes = collectionCreate(headerNodes, state);
		if (graphs->items[i].nodes == NULL) {
			EXCEPTION_SET(CORRUPT_DATA);
			fiftyoneDegreesIpiGraphFree(graphs);
			return NULL;
		}

		// Create the collection for the spans.
		graphs->items[i].spans = collectionCreate(
			graphs->items[i].info.spans,
			state);
		if (graphs->items[i].spans == NULL) {
			EXCEPTION_SET(CORRUPT_DATA);
			fiftyoneDegreesIpiGraphFree(graphs);
			return NULL;
		}
		graphs->items[i].spansCount = CollectionGetCount(
			graphs->items[i].spans);

		// Create the collection for the span bytes.
		{
			const CollectionHeader spanBytesHeader = {
				graphs->items[i].info.spanBytes.startPosition,
				graphs->items[i].info.spanBytes.length,
				graphs->items[i].info.spanBytes.length,
			};
			graphs->items[i].spanBytes = collectionCreate(
				spanBytesHeader,
				state);
		}
		if (graphs->items[i].spanBytes == NULL) {
			EXCEPTION_SET(CORRUPT_DATA);
			fiftyoneDegreesIpiGraphFree(graphs);
			return NULL;
		}

		// Create the collection for the clusters.
		graphs->items[i].clusters = collectionCreate(
			graphs->items[i].info.clusters,
			state);
		if (graphs->items[i].clusters == NULL) {
			EXCEPTION_SET(CORRUPT_DATA);
			fiftyoneDegreesIpiGraphFree(graphs);
			return NULL;
		}
		graphs->items[i].clustersCount = CollectionGetCount(
			graphs->items[i].clusters);

		// Check that the element size for the clusters is not larger than the
		// structure.
		if (graphs->items[i].clusters->elementSize > sizeof(Cluster)) {
			EXCEPTION_SET(CORRUPT_DATA);
			fiftyoneDegreesIpiGraphFree(graphs);
			return NULL;
		}
	}

	return graphs;
}

void fiftyoneDegreesIpiGraphFree(fiftyoneDegreesIpiCgArray* graphs) {
	for (uint32_t i = 0; i < graphs->count; i++) {
		FIFTYONE_DEGREES_COLLECTION_FREE(graphs->items[i].nodes);
		FIFTYONE_DEGREES_COLLECTION_FREE(graphs->items[i].spans);
		FIFTYONE_DEGREES_COLLECTION_FREE(graphs->items[i].spanBytes);
		FIFTYONE_DEGREES_COLLECTION_FREE(graphs->items[i].clusters);
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

fiftyoneDegreesIpiCgResult fiftyoneDegreesIpiGraphEvaluate(
    const fiftyoneDegreesIpiCgArray*  const graphs,
	const byte componentId,
	const fiftyoneDegreesIpAddress address,
	fiftyoneDegreesException* const exception) {

	// String builder is not needed for normal usage without tracing.
	StringBuilder sb = { NULL, 0 };

	return ipiGraphEvaluate(graphs, componentId, address, &sb, exception);
}

fiftyoneDegreesIpiCgResult fiftyoneDegreesIpiGraphEvaluateTrace(
	fiftyoneDegreesIpiCgArray* graphs,
	byte componentId,
	fiftyoneDegreesIpAddress address,
	char* buffer,
	int const length,
	fiftyoneDegreesException* exception) {
	StringBuilder sb = { buffer, length };
	StringBuilderInit(&sb);

	// Add the bytes of the IP address to the trace.
	StringBuilderAddChar(&sb, '\r');
	StringBuilderAddChar(&sb, '\n');
	StringBuilderAddChars(&sb, "IP:", sizeof("IP:") - 1);
	int ipLength = 0;
	switch (address.type) {
	case FIFTYONE_DEGREES_IP_TYPE_IPV4:
		ipLength = 4;
		break;
	case FIFTYONE_DEGREES_IP_TYPE_IPV6:
		ipLength = 16;
		break;
	}
	for (int i = 0; i < ipLength; i++) {
		StringBuilderAddInteger(&sb, address.value[i]);
		if (i < ipLength - 1) {
			StringBuilderAddChar(&sb, '.');
		}
	}

	const fiftyoneDegreesIpiCgResult result = ipiGraphEvaluate(
		graphs, 
		componentId, 
		address, 
		&sb,
		exception);
	StringBuilderAddChar(&sb, '\0');
	return result;
}
