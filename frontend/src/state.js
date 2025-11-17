import { atom } from "recoil";

export const apiKeysState = atom({
  key: "KeysState",
  default: [],
});

export const modulesState = atom({
  key: "ModulesState",
  default: [],
});

export const generalSettingsState = atom({
  key: "GeneralSettingsState",
  default: {},
});

export const newsfeedListState = atom({
  key: "NewsfeedListState",
  default: [],
});

export const newsfeedState = atom({
  key: "NewsfeedState",
  default: [],
});

export const searchHistoryState = atom({
  key: "SearchHistoryState",
  default: [],
});

// IoC Collection State for Agent workflows
export const iocCollectionState = atom({
  key: "IocCollectionState",
  default: {
    triage: [],
    malware: [],
    infrastructure: [],
    campaign: [],
  },
});
