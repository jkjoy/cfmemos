import { useCallback, useMemo, useState } from "react";

const useLoading = (initialState = true) => {
  const [state, setState] = useState({ isLoading: initialState, isFailed: false, isSucceed: false });
  const setLoading = useCallback(() => {
    setState({
      isLoading: true,
      isFailed: false,
      isSucceed: false,
    });
  }, []);

  const setFinish = useCallback(() => {
    setState({
      isLoading: false,
      isFailed: false,
      isSucceed: true,
    });
  }, []);

  const setError = useCallback(() => {
    setState({
      isLoading: false,
      isFailed: true,
      isSucceed: false,
    });
  }, []);

  return useMemo(
    () => ({
      ...state,
      setLoading,
      setFinish,
      setError,
    }),
    [setError, setFinish, setLoading, state]
  );
};

export default useLoading;
