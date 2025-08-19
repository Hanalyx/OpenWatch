import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import { api } from '../../services/api';

interface Profile {
  id: string;
  title: string;
  description: string;
}

interface Content {
  id: string;
  name: string;
  filename: string;
  type: 'datastream' | 'xccdf';
  profiles: Profile[];
  uploaded_at: string;
  size: number;
}

interface ContentState {
  contents: Content[];
  selectedContent: Content | null;
  isLoading: boolean;
  error: string | null;
  uploadProgress: number;
}

const initialState: ContentState = {
  contents: [],
  selectedContent: null,
  isLoading: false,
  error: null,
  uploadProgress: 0,
};

export const fetchContents = createAsyncThunk('content/fetchContents', async () => {
  const response = await api.get('/content');
  return response.data;
});

export const uploadContent = createAsyncThunk(
  'content/uploadContent',
  async (file: File, { dispatch }) => {
    const response = await api.uploadFile('/content/upload', file, (progress) => {
      dispatch(updateUploadProgress(progress));
    });
    return response.data;
  }
);

export const deleteContent = createAsyncThunk(
  'content/deleteContent',
  async (id: string) => {
    await api.delete(`/content/${id}`);
    return id;
  }
);

const contentSlice = createSlice({
  name: 'content',
  initialState,
  reducers: {
    selectContent: (state, action) => {
      state.selectedContent = action.payload;
    },
    updateUploadProgress: (state, action) => {
      state.uploadProgress = action.payload;
    },
    clearError: (state) => {
      state.error = null;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchContents.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(fetchContents.fulfilled, (state, action) => {
        state.isLoading = false;
        state.contents = action.payload;
      })
      .addCase(fetchContents.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.error.message || 'Failed to fetch content';
      })
      .addCase(uploadContent.pending, (state) => {
        state.uploadProgress = 0;
      })
      .addCase(uploadContent.fulfilled, (state, action) => {
        state.contents.push(action.payload);
        state.uploadProgress = 0;
      })
      .addCase(uploadContent.rejected, (state, action) => {
        state.uploadProgress = 0;
        state.error = action.error.message || 'Failed to upload content';
      })
      .addCase(deleteContent.fulfilled, (state, action) => {
        state.contents = state.contents.filter((c) => c.id !== action.payload);
        if (state.selectedContent?.id === action.payload) {
          state.selectedContent = null;
        }
      });
  },
});

export const { selectContent, updateUploadProgress, clearError } = contentSlice.actions;
export default contentSlice.reducer;