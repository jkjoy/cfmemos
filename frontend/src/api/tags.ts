import apiClient from './client';

interface TagApiParams {
  creatorId?: number;
  limit?: number;
}

/**
 * Tag API Client
 * Provides methods to interact with tag endpoints
 */
export const tagAPI = {
  /**
   * List all tags
   * @param {number} creatorId - Optional creator ID to filter tags
   * @returns {Promise<Array>} List of tags with memo counts
   */
  async list(creatorId: number | null = null) {
    const params: TagApiParams = {};
    if (creatorId) params.creatorId = creatorId;

    return apiClient.get('/tag', { params });
  },

  /**
   * Create a new tag
   * @param {string} name - Tag name
   * @returns {Promise<Object>} Created tag
   */
  async create(name: string) {
    return apiClient.post('/tag', { name });
  },

  /**
   * Get tag suggestions (most used tags)
   * @param {number} limit - Number of suggestions to return
   * @returns {Promise<Array>} List of suggested tags
   */
  async suggestions(limit = 10) {
    return apiClient.get('/tag/suggestion', { params: { limit } });
  },

  /**
   * Delete a tag by name
   * @param {string} name - Tag name to delete
   * @returns {Promise<Object>} Deletion result
   */
  async delete(name: string) {
    return apiClient.post('/tag/delete', { name });
  },

  /**
   * Delete a tag by ID
   * @param {number} id - Tag ID to delete
   * @returns {Promise<Object>} Deletion result
   */
  async deleteById(id: number) {
    return apiClient.delete(`/tag/${id}`);
  }
};
