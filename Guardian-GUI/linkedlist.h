#pragma once


typedef struct lEntry {
	lEntry* Flink;
	lEntry* Blink;
} lEntry, *PlEntry;

typedef struct ListHeader {
	lEntry Entry;
	int EntryCount;
} ListHeader, *PListHeader;




void InitializeListHeader(PListHeader* PHeader);
void PushEntry(PListHeader ListHeader, PlEntry Entry);
void PushEntryTail(PListHeader ListHeader, PlEntry Entry);
PlEntry PopEntry(PListHeader ListHeader);
PlEntry PopEntryTail(PListHeader ListHeader);
PlEntry RemoveEntry(PListHeader Header, PlEntry Entry);
void InsertEntry(PlEntry Prev, PlEntry next);

