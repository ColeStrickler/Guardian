#include "linkedlist.h"

void InitializeListHeader(PListHeader* PHeader)
{
	auto header = new ListHeader();
	header->Entry.Flink = nullptr;
	header->Entry.Blink = nullptr;
	header->EntryCount = 0;
	*PHeader = header;
	return;
}


void PushEntry(PListHeader ListHeader, PlEntry Entry)
{
	if (ListHeader->Entry.Flink == nullptr) {
		ListHeader->Entry.Flink = Entry;
		ListHeader->Entry.Blink = Entry;
		Entry->Blink = &ListHeader->Entry;
		ListHeader->EntryCount++;
		return;
	}
	else {
		auto next = ListHeader->Entry.Flink;
		ListHeader->Entry.Flink = Entry;
		Entry->Blink = &ListHeader->Entry;
		Entry->Flink = next;
		next->Blink = Entry;
		ListHeader->EntryCount++;
		return;
	}
}



void PushEntryTail(PListHeader ListHeader, PlEntry Entry)
{
	if (ListHeader->Entry.Blink == nullptr) {
		ListHeader->Entry.Flink = Entry;
		ListHeader->Entry.Blink = Entry;
		Entry->Blink = &ListHeader->Entry;
		ListHeader->EntryCount++;
		return;
	}
	else {
		auto back = ListHeader->Entry.Blink;
		ListHeader->Entry.Blink = Entry;
		Entry->Flink = &ListHeader->Entry;
		Entry->Blink = back;
		back->Flink = Entry;
		ListHeader->EntryCount++;
		return;
	}
}


PlEntry PopEntry(PListHeader ListHeader)
{
	if (ListHeader->Entry.Flink == nullptr) {
		return nullptr;
	}
	else {
		auto popped = ListHeader->Entry.Flink;
		auto next = popped->Flink;
		ListHeader->Entry.Flink = next;
		next->Blink = &ListHeader->Entry;
		popped->Flink = nullptr;
		popped->Blink = nullptr;
		ListHeader->EntryCount--;
		return popped;
	}
}


PlEntry PopEntryTail(PListHeader ListHeader)
{
	if (ListHeader->Entry.Blink == nullptr) {
		return nullptr;
	}
	else {
		auto popped = ListHeader->Entry.Blink;
		auto prev = popped->Blink;
		ListHeader->Entry.Blink = prev;
		prev->Flink = &ListHeader->Entry;
		popped->Flink = nullptr;
		popped->Blink = nullptr;
		ListHeader->EntryCount--;
		return popped;
	}
}


PlEntry RemoveEntry(PListHeader ListHeader, PlEntry Entry)
{
	auto prev = Entry->Blink;
	auto next = Entry->Flink;
	prev->Flink = next;
	next->Blink = prev;
	Entry->Blink = nullptr;
	Entry->Flink = nullptr;
	ListHeader->EntryCount--;
	return Entry;
}


void InsertEntry(PListHeader ListHeader, PlEntry InsertAfter, PlEntry InsertEntry)
{
	auto next = InsertAfter->Flink;
	InsertAfter->Flink = InsertEntry;
	next->Blink = InsertEntry;
	InsertEntry->Blink = InsertAfter;
	InsertEntry->Flink = next;
	ListHeader->EntryCount++;
	return;
}

