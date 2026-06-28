import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Plus, Trash2 } from 'lucide-react';

interface KeyValuePair {
  key: string;
  value: string;
}

interface UrlEncodedEditorProps {
  body: string;
  onChange: (body: string) => void;
  className?: string;
}

const UrlEncodedEditor = ({
  body,
  onChange,
  className,
}: UrlEncodedEditorProps) => {
  const [pairs, setPairs] = useState<KeyValuePair[]>([{ key: '', value: '' }]);

  useEffect(() => {
    if (body.trim()) {
      try {
        const params = new URLSearchParams(body);
        const newPairs: KeyValuePair[] = [];
        params.forEach((value, key) => {
          newPairs.push({ key, value });
        });
        if (newPairs.length > 0) {
          setPairs([...newPairs, { key: '', value: '' }]);
        } else {
          setPairs([{ key: '', value: '' }]);
        }
      } catch {
        setPairs([{ key: '', value: '' }]);
      }
    } else {
      setPairs([{ key: '', value: '' }]);
    }
  }, [body]);

  const updateBody = (newPairs: KeyValuePair[]) => {
    const validPairs = newPairs.filter((pair) => pair.key.trim() !== '');
    const params = new URLSearchParams();
    validPairs.forEach((pair) => {
      params.append(pair.key.trim(), pair.value);
    });
    onChange(params.toString());
  };

  const addPair = () => {
    setPairs([...pairs, { key: '', value: '' }]);
  };

  const removePair = (index: number) => {
    const newPairs = pairs.filter((_, i) => i !== index);
    setPairs(newPairs);
    updateBody(newPairs);
  };
